<?php

/**
 * Deepgram Live Text-to-Speech Starter - PHP (Ratchet)
 *
 * WebSocket proxy server that forwards messages bidirectionally between
 * browser clients and Deepgram's Live TTS API (wss://api.deepgram.com/v1/speak).
 *
 * Key Features:
 * - WebSocket proxy: /api/live-text-to-speech -> Deepgram TTS
 * - JWT session auth via access_token.<jwt> subprotocol
 * - REST endpoints: GET /api/session, GET /api/metadata
 * - CORS enabled for frontend communication
 * - Graceful shutdown on SIGTERM/SIGINT
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   WS   /api/live-text-to-speech    - WebSocket proxy to Deepgram TTS (auth required)
 *
 * Usage: php server.php
 */

require __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Yosymfony\Toml\Toml;
use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Http\HttpServerInterface;
use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use React\EventLoop\Loop;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Matcher\UrlMatcher;
use Ratchet\Http\Router;
use Ratchet\WebSocket\WsServer;

// ============================================================================
// ENVIRONMENT LOADING
// ============================================================================

Dotenv::createImmutable(__DIR__)->safeLoad();

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

/**
 * Deepgram Live TTS WebSocket URL
 */
$DEEPGRAM_TTS_URL = 'wss://api.deepgram.com/v1/speak';

/**
 * Server configuration - These can be overridden via environment variables
 */
$PORT = (int) ($_ENV['PORT'] ?? '8081');
$HOST = $_ENV['HOST'] ?? '0.0.0.0';

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/**
 * Session secret for signing JWTs.
 * In production, set SESSION_SECRET in .env for persistent sessions.
 */
$SESSION_SECRET = $_ENV['SESSION_SECRET'] ?? bin2hex(random_bytes(32));

/** JWT expiry time in seconds (1 hour) */
$JWT_EXPIRY = 3600;

/**
 * Creates a signed JWT session token.
 *
 * @return string Signed JWT token
 */
function createSessionToken(): string
{
    global $SESSION_SECRET, $JWT_EXPIRY;

    $now = time();
    $payload = [
        'iat' => $now,
        'exp' => $now + $JWT_EXPIRY,
    ];

    return JWT::encode($payload, $SESSION_SECRET, 'HS256');
}

/**
 * Validates a JWT from the WebSocket access_token.<jwt> subprotocol.
 *
 * @param string|null $protocolHeader The Sec-WebSocket-Protocol header value
 * @return string|null The matching protocol string if valid, null otherwise
 */
function validateWsToken(?string $protocolHeader): ?string
{
    global $SESSION_SECRET;

    if ($protocolHeader === null || $protocolHeader === '') {
        return null;
    }

    $protocols = array_map('trim', explode(',', $protocolHeader));

    foreach ($protocols as $proto) {
        if (str_starts_with($proto, 'access_token.')) {
            $token = substr($proto, strlen('access_token.'));
            try {
                JWT::decode($token, new Key($SESSION_SECRET, 'HS256'));
                return $proto;
            } catch (\Exception $e) {
                return null;
            }
        }
    }

    return null;
}

// ============================================================================
// API KEY LOADING - Load Deepgram API key from .env
// ============================================================================

/**
 * Loads the Deepgram API key from environment variables.
 * Exits with a helpful error message if not found.
 *
 * @return string The Deepgram API key
 */
function loadApiKey(): string
{
    $apiKey = $_ENV['DEEPGRAM_API_KEY'] ?? '';

    if (empty($apiKey)) {
        fwrite(STDERR, "\nERROR: Deepgram API key not found!\n\n");
        fwrite(STDERR, "Please set your API key using one of these methods:\n\n");
        fwrite(STDERR, "1. Create a .env file (recommended):\n");
        fwrite(STDERR, "   DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "2. Environment variable:\n");
        fwrite(STDERR, "   export DEEPGRAM_API_KEY=your_api_key_here\n\n");
        fwrite(STDERR, "Get your API key at: https://console.deepgram.com\n\n");
        exit(1);
    }

    return $apiKey;
}

$apiKey = loadApiKey();

// ============================================================================
// HELPER FUNCTIONS - Safe close codes, CORS headers
// ============================================================================

/**
 * Reserved WebSocket close codes that must not be sent by applications.
 */
const RESERVED_CLOSE_CODES = [1004, 1005, 1006, 1015];

/**
 * Returns a safe WebSocket close code, falling back to 1000 for reserved codes.
 *
 * @param int|null $code The close code to sanitize
 * @return int A safe close code
 */
function getSafeCloseCode(?int $code): int
{
    if ($code !== null && $code >= 1000 && $code <= 4999 && !in_array($code, RESERVED_CLOSE_CODES, true)) {
        return $code;
    }
    return 1000;
}

/**
 * Returns standard CORS headers as an associative array.
 *
 * @return array CORS headers
 */
function corsHeaders(): array
{
    return [
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers' => 'Content-Type, Authorization',
    ];
}

/**
 * Creates an HTTP response with CORS headers.
 *
 * @param int    $status  HTTP status code
 * @param array  $headers Additional headers
 * @param string $body    Response body
 * @return GuzzleResponse
 */
function httpResponse(int $status, array $headers, string $body): GuzzleResponse
{
    return new GuzzleResponse($status, array_merge(corsHeaders(), $headers), $body);
}

/**
 * Creates a JSON HTTP response with CORS headers.
 *
 * @param mixed $data   Data to encode as JSON
 * @param int   $status HTTP status code
 * @return GuzzleResponse
 */
function jsonResponse(mixed $data, int $status = 200): GuzzleResponse
{
    return httpResponse(
        $status,
        ['Content-Type' => 'application/json'],
        json_encode($data, JSON_UNESCAPED_SLASHES)
    );
}

// ============================================================================
// WEBSOCKET PROXY - Bidirectional proxy to Deepgram Live TTS API
// ============================================================================

/**
 * WebSocket proxy handler for Deepgram Live Text-to-Speech.
 *
 * Validates JWT from access_token.<jwt> subprotocol on connection,
 * opens a connection to Deepgram's TTS WebSocket, and forwards all
 * messages bidirectionally between client and Deepgram.
 */
class LiveTextToSpeechProxy implements MessageComponentInterface
{
    /** @var \SplObjectStorage<ConnectionInterface, \Ratchet\Client\WebSocket|null> */
    private \SplObjectStorage $clients;

    private string $apiKey;
    private string $deepgramUrl;

    public function __construct(string $apiKey, string $deepgramUrl)
    {
        $this->clients = new \SplObjectStorage();
        $this->apiKey = $apiKey;
        $this->deepgramUrl = $deepgramUrl;
    }

    /**
     * Called when a new client WebSocket connection is opened.
     * Validates JWT, parses query parameters, connects to Deepgram.
     */
    public function onOpen(ConnectionInterface $conn): void
    {
        echo "Client connected to /api/live-text-to-speech\n";

        // Validate JWT from subprotocol
        $httpRequest = $conn->httpRequest;
        $protocolHeader = $httpRequest->getHeaderLine('Sec-WebSocket-Protocol');
        $validProto = validateWsToken($protocolHeader);

        if ($validProto === null) {
            echo "WebSocket auth failed: invalid or missing token\n";
            $conn->close();
            return;
        }

        // Parse query parameters from the WebSocket URL
        $queryString = $httpRequest->getUri()->getQuery();
        parse_str($queryString, $params);

        $model = $params['model'] ?? 'aura-asteria-en';
        $encoding = $params['encoding'] ?? 'linear16';
        $sampleRate = $params['sample_rate'] ?? '48000';
        $container = $params['container'] ?? 'none';

        // Build Deepgram WebSocket URL with query parameters
        $dgUrl = $this->deepgramUrl
            . '?model=' . urlencode($model)
            . '&encoding=' . urlencode($encoding)
            . '&sample_rate=' . urlencode($sampleRate)
            . '&container=' . urlencode($container);

        echo "Connecting to Deepgram TTS: model={$model}, encoding={$encoding}, sample_rate={$sampleRate}\n";

        // Store the client with null Deepgram connection initially
        $this->clients->attach($conn, null);

        // Connect to Deepgram using pawl (ReactPHP WebSocket client)
        $connector = new \Ratchet\Client\Connector(Loop::get());
        $connector($dgUrl, [], [
            'Authorization' => 'Token ' . $this->apiKey,
        ])->then(
            function (\Ratchet\Client\WebSocket $deepgramWs) use ($conn) {
                echo "Connected to Deepgram TTS API\n";

                // Store the Deepgram connection associated with this client
                $this->clients[$conn] = $deepgramWs;

                // Forward messages from Deepgram to client (binary audio + JSON)
                $deepgramWs->on('message', function (\Ratchet\RFC6455\Messaging\MessageInterface $msg) use ($conn) {
                    if ($conn->writable ?? true) {
                        // Detect binary vs text: if it's a binary frame, send as binary
                        if ($msg->isBinary()) {
                            $conn->send(new \Ratchet\RFC6455\Messaging\Frame(
                                $msg->getPayload(),
                                true,
                                \Ratchet\RFC6455\Messaging\Frame::OP_BINARY
                            ));
                        } else {
                            $conn->send($msg->getPayload());
                        }
                    }
                });

                // Handle Deepgram connection close
                $deepgramWs->on('close', function ($code = null, $reason = null) use ($conn) {
                    echo "Deepgram connection closed: {$code} {$reason}\n";
                    $closeCode = getSafeCloseCode($code);
                    $conn->close($closeCode);
                });

                // Handle Deepgram errors
                $deepgramWs->on('error', function (\Exception $e) use ($conn) {
                    echo "Deepgram WebSocket error: {$e->getMessage()}\n";
                    $conn->send(json_encode([
                        'type' => 'Error',
                        'description' => $e->getMessage() ?: 'Deepgram connection error',
                        'code' => 'PROVIDER_ERROR',
                    ]));
                    $conn->close();
                });
            },
            function (\Exception $e) use ($conn) {
                echo "Failed to connect to Deepgram: {$e->getMessage()}\n";
                $conn->send(json_encode([
                    'type' => 'Error',
                    'description' => 'Failed to establish proxy connection',
                    'code' => 'CONNECTION_FAILED',
                ]));
                $conn->close();
            }
        );
    }

    /**
     * Called when a message is received from the client.
     * Forwards it to the Deepgram WebSocket connection.
     */
    public function onMessage(ConnectionInterface $from, $msg): void
    {
        if (!$this->clients->contains($from)) {
            return;
        }

        $deepgramWs = $this->clients[$from];

        if ($deepgramWs !== null) {
            $deepgramWs->send($msg);
        }
    }

    /**
     * Called when a client connection is closed.
     * Closes the associated Deepgram connection.
     */
    public function onClose(ConnectionInterface $conn): void
    {
        echo "Client disconnected\n";

        if ($this->clients->contains($conn)) {
            $deepgramWs = $this->clients[$conn];
            if ($deepgramWs !== null) {
                $deepgramWs->close();
            }
            $this->clients->detach($conn);
        }
    }

    /**
     * Called when an error occurs on a client connection.
     * Closes the connection.
     */
    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        echo "Client WebSocket error: {$e->getMessage()}\n";

        if ($this->clients->contains($conn)) {
            $deepgramWs = $this->clients[$conn];
            if ($deepgramWs !== null) {
                $deepgramWs->close();
            }
            $this->clients->detach($conn);
        }

        $conn->close();
    }

    /**
     * Returns the number of active connections.
     *
     * @return int Active connection count
     */
    public function getConnectionCount(): int
    {
        return $this->clients->count();
    }

    /**
     * Closes all active connections for graceful shutdown.
     */
    public function closeAll(): void
    {
        foreach ($this->clients as $conn) {
            $deepgramWs = $this->clients[$conn];
            if ($deepgramWs !== null) {
                $deepgramWs->close();
            }
            $conn->close(1001);
        }
    }
}

// ============================================================================
// HTTP HANDLER - REST endpoints (/api/session, /api/metadata)
// ============================================================================

/**
 * HTTP handler for REST API endpoints.
 *
 * Serves GET /api/session and GET /api/metadata on the same port
 * as the WebSocket server using Ratchet's HttpServerInterface.
 */
class HttpHandler implements HttpServerInterface
{
    /**
     * Called when an HTTP request is received.
     * Dispatches to the appropriate handler based on path and method.
     */
    public function onOpen(ConnectionInterface $conn, ?RequestInterface $request = null): void
    {
        $path = $request->getUri()->getPath();
        $method = $request->getMethod();

        // Handle CORS preflight
        if ($method === 'OPTIONS') {
            $response = httpResponse(204, [], '');
            $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
            $conn->close();
            return;
        }

        // GET /api/session - Issue JWT session token
        if ($path === '/api/session' && $method === 'GET') {
            $token = createSessionToken();
            $response = jsonResponse(['token' => $token]);
            $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
            $conn->close();
            return;
        }

        // GET /api/metadata - Return metadata from deepgram.toml
        if ($path === '/api/metadata' && $method === 'GET') {
            try {
                $tomlPath = __DIR__ . '/deepgram.toml';

                if (!file_exists($tomlPath)) {
                    $response = jsonResponse([
                        'error' => 'INTERNAL_SERVER_ERROR',
                        'message' => 'deepgram.toml not found',
                    ], 500);
                    $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
                    $conn->close();
                    return;
                }

                $config = Toml::parseFile($tomlPath);
                $meta = $config['meta'] ?? null;

                if ($meta === null) {
                    $response = jsonResponse([
                        'error' => 'INTERNAL_SERVER_ERROR',
                        'message' => 'Missing [meta] section in deepgram.toml',
                    ], 500);
                    $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
                    $conn->close();
                    return;
                }

                $response = jsonResponse($meta);
                $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
                $conn->close();
                return;
            } catch (\Exception $e) {
                fwrite(STDERR, "Error reading metadata: {$e->getMessage()}\n");
                $response = jsonResponse([
                    'error' => 'INTERNAL_SERVER_ERROR',
                    'message' => 'Failed to read metadata from deepgram.toml',
                ], 500);
                $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
                $conn->close();
                return;
            }
        }

        // GET /health - Simple health check
        if ($path === '/health' && $method === 'GET') {
            $response = jsonResponse(['status' => 'ok']);
            $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
            $conn->close();
            return;
        }

        // 404 for unknown API routes
        $response = jsonResponse([
            'error' => 'NOT_FOUND',
            'message' => 'Not found',
        ], 404);
        $conn->send(\GuzzleHttp\Psr7\Message::toString($response));
        $conn->close();
    }

    public function onMessage(ConnectionInterface $from, $msg): void
    {
        // HTTP handler does not expect WebSocket messages
    }

    public function onClose(ConnectionInterface $conn): void
    {
        // Connection closed
    }

    public function onError(ConnectionInterface $conn, \Exception $e): void
    {
        fwrite(STDERR, "HTTP handler error: {$e->getMessage()}\n");
        $conn->close();
    }
}

// ============================================================================
// SERVER SETUP - Ratchet IoServer with Router (WS + HTTP on same port)
// ============================================================================

// Create the WebSocket proxy handler
$wsProxy = new LiveTextToSpeechProxy($apiKey, $DEEPGRAM_TTS_URL);

// Create the WsServer wrapping the proxy, with subprotocol handling
$wsServer = new WsServer($wsProxy);
$wsServer->setStrictSubProtocolCheck(false);

// Custom negotiator to accept access_token.* subprotocols
$customNegotiator = new class(new \Ratchet\RFC6455\Handshake\RequestVerifier()) extends \Ratchet\RFC6455\Handshake\ServerNegotiator {
    public function __construct(\Ratchet\RFC6455\Handshake\RequestVerifier $verifier) {
        parent::__construct($verifier);
        $this->setStrictSubProtocolCheck(false);
    }
    public function handshake(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface {
        $response = parent::handshake($request);
        if ($response->getStatusCode() === 101 && !$response->hasHeader('Sec-WebSocket-Protocol')) {
            $protocols = $request->getHeader('Sec-WebSocket-Protocol');
            $all = array_map('trim', explode(',', implode(',', $protocols)));
            foreach ($all as $proto) {
                if (str_starts_with($proto, 'access_token.')) {
                    $response = $response->withHeader('Sec-WebSocket-Protocol', $proto);
                    break;
                }
            }
        }
        return $response;
    }
};
$ref = new \ReflectionProperty($wsServer, 'handshakeNegotiator');
$ref->setAccessible(true);
$ref->setValue($wsServer, $customNegotiator);

// Create the HTTP handler for REST endpoints
$httpHandler = new HttpHandler();

// Set up Symfony routing to dispatch WebSocket vs HTTP on the same port
$routes = new RouteCollection();

// WebSocket route: /api/live-text-to-speech
$routes->add('ws-live-tts', new Route(
    '/api/live-text-to-speech',
    ['_controller' => $wsServer],
    [],
    [],
    null,
    [],
    ['GET']
));

// HTTP route: /api/session
$routes->add('session', new Route(
    '/api/session',
    ['_controller' => $httpHandler],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// HTTP route: /api/metadata
$routes->add('metadata', new Route(
    '/api/metadata',
    ['_controller' => $httpHandler],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// HTTP route: /health
$routes->add('health', new Route(
    '/health',
    ['_controller' => $httpHandler],
    [],
    [],
    null,
    [],
    ['GET', 'OPTIONS']
));

// Catch-all fallback (404)
$routes->add('fallback', new Route(
    '/{path}',
    ['_controller' => $httpHandler],
    ['path' => '.*']
));

$urlMatcher = new UrlMatcher($routes, new RequestContext());
$router = new Router($urlMatcher);

// Create the HTTP server wrapping the router
$httpServer = new HttpServer($router);

// Create the IO server (let IoServer::factory manage the event loop)
$server = IoServer::factory(
    $httpServer,
    (int)$PORT,
    $HOST
);

// ============================================================================
// GRACEFUL SHUTDOWN - Clean up on SIGTERM/SIGINT
// ============================================================================

/**
 * Handles graceful shutdown on SIGTERM/SIGINT.
 * Closes all active WebSocket connections and stops the event loop.
 */
$shutdown = function (int $signal) use ($wsProxy, $server): void {
    $signalName = $signal === SIGTERM ? 'SIGTERM' : 'SIGINT';
    echo "\n{$signalName} received: starting graceful shutdown...\n";

    $count = $wsProxy->getConnectionCount();
    echo "Closing {$count} active WebSocket connection(s)...\n";
    $wsProxy->closeAll();

    $server->socket->close();
    echo "Server socket closed\n";

    $server->loop->addTimer(1, function () use ($server) {
        echo "Shutdown complete\n";
        $server->loop->stop();
    });
};

// Register signal handlers (only works with pcntl extension)
if (function_exists('pcntl_signal')) {
    $server->loop->addSignal(SIGTERM, $shutdown);
    $server->loop->addSignal(SIGINT, $shutdown);
}

// ============================================================================
// START SERVER
// ============================================================================

echo "\n" . str_repeat('=', 70) . "\n";
echo "Backend API Server running at http://localhost:{$PORT}\n";
echo "\n";
echo "GET  /api/session\n";
echo "WS   /api/live-text-to-speech (auth required)\n";
echo "GET  /api/metadata\n";
echo "GET  /health\n";
echo str_repeat('=', 70) . "\n\n";

$server->run();
