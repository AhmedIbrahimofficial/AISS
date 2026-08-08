# Laravel Hybrid Architecture Blueprint

> **Status:** Ready to drop in. Laravel does not yet exist in this repo.
> Run `composer create-project laravel/laravel laravel-api` in this directory,
> then implement the structure below inside `laravel-api/`.

---

## Architecture Overview

```
Browser (Next.js 16 + Clerk)
        │
        │  Clerk session cookie / JWT
        ▼
Next.js API Routes  ←  BFF (already implemented)
        │  /api/proxy/*  /api/scan  /api/threats/*
        │
        │  REST (JSON over HTTP)
        ▼
Laravel API  (port 8001)        ← NEW — add this
        │  Auth, Users, Reports, Dashboard, FileUpload
        │  Stores everything in PostgreSQL
        │
        │  Internal service token  (FASTAPI_SERVICE_TOKEN)
        ▼
FastAPI Security Engine  (port 8000)  ← EXISTS — already running
        │  Nmap, YARA, AI, Threats, Kill Chain
        │  Returns JSON
        │
        ▼
PostgreSQL Database  ← shared
```

---

## Folder Structure

```
laravel-api/
├── app/
│   ├── Http/
│   │   ├── Controllers/           # Thin — call services, return responses
│   │   │   ├── Auth/
│   │   │   │   ├── AuthController.php
│   │   │   │   └── ProfileController.php
│   │   │   ├── Dashboard/
│   │   │   │   └── DashboardController.php
│   │   │   ├── Scan/
│   │   │   │   └── ScanController.php     ← calls FastApiService
│   │   │   ├── Reports/
│   │   │   │   └── ReportController.php
│   │   │   ├── Files/
│   │   │   │   └── FileUploadController.php
│   │   │   └── Admin/
│   │   │       └── UserController.php
│   │   │
│   │   ├── Middleware/
│   │   │   ├── EnsureEmailVerified.php
│   │   │   ├── RoleMiddleware.php         ← role('admin'), role('analyst')
│   │   │   └── AuditLog.php              ← writes to audit_logs table
│   │   │
│   │   └── Requests/                     ← Form Request validation (SOLID — SRP)
│   │       ├── StartScanRequest.php
│   │       ├── UploadFileRequest.php
│   │       └── UpdateProfileRequest.php
│   │
│   ├── Services/
│   │   ├── FastApiService.php             ← THE key service (see below)
│   │   ├── ScanOrchestrationService.php  ← coordinates scan flow
│   │   ├── ReportService.php
│   │   └── NotificationService.php
│   │
│   ├── Repositories/
│   │   ├── Contracts/                    ← Interfaces (Dependency Inversion)
│   │   │   ├── ScanRepositoryInterface.php
│   │   │   └── ThreatRepositoryInterface.php
│   │   ├── ScanRepository.php
│   │   └── ThreatRepository.php
│   │
│   ├── Models/
│   │   ├── User.php
│   │   ├── ScanJob.php
│   │   ├── ThreatRecord.php
│   │   ├── Report.php
│   │   └── AuditLog.php
│   │
│   └── Jobs/                             ← Queue workers
│       ├── RunSecurityScan.php           ← dispatched to queue, calls FastAPI
│       └── GenerateReport.php
│
├── routes/
│   └── api.php                           ← all API routes, versioned under /api/v1
│
├── database/
│   └── migrations/
│       ├── xxxx_create_scan_jobs_table.php
│       ├── xxxx_create_threat_records_table.php
│       └── xxxx_create_audit_logs_table.php
│
└── config/
    └── fastapi.php                        ← FastAPI connection config
```

---

## FastApiService.php — Complete Implementation

```php
<?php

namespace App\Services;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;

/**
 * FastApiService
 *
 * WHY THIS EXISTS:
 *   Single point of contact between Laravel and the FastAPI security engine.
 *   Every HTTP call to FastAPI goes through here — never Http::get() directly
 *   in a controller. This gives us:
 *     - One place to change the FastAPI base URL
 *     - Automatic auth header injection (internal service token)
 *     - Timeout + retry configuration in one place
 *     - Structured error handling — no unhandled exceptions in controllers
 *     - Easy to mock in tests
 *
 * CONFIGURATION (config/fastapi.php):
 *   'base_url'      => env('FASTAPI_URL', 'http://localhost:8000'),
 *   'timeout'       => env('FASTAPI_TIMEOUT', 10),
 *   'retry_times'   => env('FASTAPI_RETRY_TIMES', 2),
 *   'retry_sleep'   => env('FASTAPI_RETRY_SLEEP', 300), // milliseconds
 *   'service_token' => env('FASTAPI_SERVICE_TOKEN', ''),
 */
class FastApiService
{
    private string $baseUrl;
    private int    $timeout;
    private int    $retryTimes;
    private int    $retrySleep;
    private string $serviceToken;

    public function __construct()
    {
        $this->baseUrl      = config('fastapi.base_url', 'http://localhost:8000');
        $this->timeout      = (int) config('fastapi.timeout', 10);
        $this->retryTimes   = (int) config('fastapi.retry_times', 2);
        $this->retrySleep   = (int) config('fastapi.retry_sleep', 300);
        $this->serviceToken = config('fastapi.service_token', '');
    }

    // ── Threat endpoints ─────────────────────────────────────────────

    public function getThreatStats(): array
    {
        return $this->get('/api/threats/stats');
    }

    public function getActiveThreats(): array
    {
        return $this->get('/api/threats/active');
    }

    public function resolveThreat(string $threatId, string $note = 'Resolved'): array
    {
        return $this->post("/api/threats/{$threatId}/resolve", ['note' => $note]);
    }

    // ── Scanner endpoints ─────────────────────────────────────────────

    /**
     * Trigger a security scan on a target.
     *
     * Laravel scan flow:
     *   ScanController → ScanOrchestrationService → FastApiService::runScan()
     *                                             → store result in DB
     *                                             → return to controller
     */
    public function runScan(string $target, string $scanType = 'full', ?string $userId = null): array
    {
        return $this->post('/api/scanner/scan', [
            'target'    => $target,
            'scan_type' => $scanType,
            'user_id'   => $userId ?? '',
        ], timeout: 30); // scans can be slow
    }

    public function simulateThreats(int $count = 3, float $delay = 1.0): array
    {
        return $this->post('/api/scanner/simulate', [
            'count' => $count,
            'delay' => $delay,
        ]);
    }

    // ── System endpoints ──────────────────────────────────────────────

    public function getSystemHealth(): array
    {
        return $this->get('/api/system/health');
    }

    public function getKillChain(): array
    {
        return $this->get('/api/kill-chain');
    }

    // ── AI endpoints ──────────────────────────────────────────────────

    public function analyzeWithAI(string $threatId): array
    {
        return $this->post('/api/ai/analyze', [
            'threat_id' => $threatId,
        ], timeout: 60); // Claude is slow
    }

    // ── Core HTTP methods ─────────────────────────────────────────────

    private function get(string $path, array $query = []): array
    {
        return $this->client()
            ->retry($this->retryTimes, $this->retrySleep, when: fn ($e) => $this->shouldRetry($e))
            ->get($this->baseUrl . $path, $query)
            ->throw()
            ->json();
    }

    private function post(string $path, array $body = [], int $timeout = 0): array
    {
        $client = $this->client($timeout ?: $this->timeout);
        return $client
            ->retry($this->retryTimes, $this->retrySleep, when: fn ($e) => $this->shouldRetry($e))
            ->post($this->baseUrl . $path, $body)
            ->throw()
            ->json();
    }

    private function client(int $timeout = 0): PendingRequest
    {
        $http = Http::timeout($timeout ?: $this->timeout)
            ->withHeaders([
                'Content-Type'       => 'application/json',
                'X-Internal-Service' => 'laravel-api',
            ]);

        if ($this->serviceToken) {
            $http = $http->withToken($this->serviceToken);
        }

        return $http;
    }

    /**
     * Only retry on 5xx server errors and connection failures.
     * Never retry 4xx — those are caller errors.
     */
    private function shouldRetry(\Throwable $exception): bool
    {
        if ($exception instanceof \Illuminate\Http\Client\RequestException) {
            return $exception->response->status() >= 500;
        }
        // Connection refused, DNS failure, timeout
        return true;
    }
}
```

---

## config/fastapi.php

```php
<?php

return [
    // Internal FastAPI URL — use Docker service name in production
    'base_url'      => env('FASTAPI_URL', 'http://localhost:8000'),

    // Request timeout in seconds (use higher value for AI/scan endpoints)
    'timeout'       => (int) env('FASTAPI_TIMEOUT', 10),

    // Retry on 5xx: how many times to retry
    'retry_times'   => (int) env('FASTAPI_RETRY_TIMES', 2),

    // Milliseconds between retries
    'retry_sleep'   => (int) env('FASTAPI_RETRY_SLEEP', 300),

    // Shared secret — must match INTERNAL_SERVICE_TOKEN in FastAPI .env
    'service_token' => env('FASTAPI_SERVICE_TOKEN', ''),
];
```

---

## ScanController.php — The Scan Flow

```php
<?php

namespace App\Http\Controllers\Scan;

use App\Http\Controllers\Controller;
use App\Http\Requests\StartScanRequest;
use App\Services\ScanOrchestrationService;
use Illuminate\Http\JsonResponse;

class ScanController extends Controller
{
    // Dependency Injection — no manual instantiation
    public function __construct(
        private readonly ScanOrchestrationService $scanService,
    ) {}

    /**
     * POST /api/v1/scan
     *
     * Flow:
     *   1. StartScanRequest validates input
     *   2. ScanOrchestrationService.start() calls FastApiService
     *   3. Stores result in scan_jobs table
     *   4. Returns JSON to client
     *
     * Laravel never runs the scan directly.
     * FastAPI runs the scan. Laravel stores the result.
     */
    public function start(StartScanRequest $request): JsonResponse
    {
        $result = $this->scanService->start(
            target:   $request->validated('target'),
            scanType: $request->validated('scan_type', 'full'),
            userId:   $request->user()->id,
        );

        return response()->json($result, 201);
    }

    public function show(string $jobId): JsonResponse
    {
        $job = $this->scanService->getJob($jobId, $request->user()->id);
        return response()->json($job);
    }
}
```

---

## ScanOrchestrationService.php

```php
<?php

namespace App\Services;

use App\Models\ScanJob;
use App\Repositories\Contracts\ScanRepositoryInterface;
use Illuminate\Support\Str;

class ScanOrchestrationService
{
    public function __construct(
        private readonly FastApiService           $fastApi,
        private readonly ScanRepositoryInterface  $scanRepo,
    ) {}

    public function start(string $target, string $scanType, string $userId): array
    {
        // 1. Create a pending job record
        $job = $this->scanRepo->create([
            'id'        => Str::uuid(),
            'user_id'   => $userId,
            'target'    => $target,
            'scan_type' => $scanType,
            'status'    => 'running',
        ]);

        try {
            // 2. Call FastAPI — Laravel NEVER runs the scan
            $result = $this->fastApi->runScan($target, $scanType, $userId);

            // 3. Store the result
            $this->scanRepo->complete($job->id, $result);

            return array_merge($job->toArray(), ['fastapi_result' => $result]);

        } catch (\Throwable $e) {
            $this->scanRepo->fail($job->id, $e->getMessage());
            throw $e;
        }
    }
}
```

---

## routes/api.php

```php
<?php

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Scan\ScanController;
use App\Http\Controllers\Dashboard\DashboardController;
use App\Http\Controllers\Reports\ReportController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    // ── Public ────────────────────────────────────────────────────────
    Route::post('/auth/register', [AuthController::class, 'register']);
    Route::post('/auth/login',    [AuthController::class, 'login']);

    // ── Authenticated ─────────────────────────────────────────────────
    Route::middleware(['auth:sanctum', 'verified'])->group(function () {

        Route::get('/me', [AuthController::class, 'me']);

        // Dashboard — aggregates FastAPI + DB data
        Route::get('/dashboard', [DashboardController::class, 'index']);

        // Scan flow — Laravel validates, FastAPI scans, Laravel stores
        Route::post('/scan',        [ScanController::class, 'start']);
        Route::get('/scan/{jobId}', [ScanController::class, 'show']);

        // Reports
        Route::get('/reports', [ReportController::class, 'index']);

        // ── Admin only ─────────────────────────────────────────────────
        Route::middleware('role:admin')->group(function () {
            Route::get('/users', [UserController::class, 'index']);
            Route::put('/users/{id}', [UserController::class, 'update']);
        });
    });
});
```

---

## Laravel .env additions

```dotenv
# FastAPI Security Engine
FASTAPI_URL=http://localhost:8000
FASTAPI_TIMEOUT=10
FASTAPI_RETRY_TIMES=2
FASTAPI_RETRY_SLEEP=300
FASTAPI_SERVICE_TOKEN=dev-change-this-in-production   # same as FastAPI INTERNAL_SERVICE_TOKEN

# PostgreSQL (shared with FastAPI)
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=aiss_db
DB_USERNAME=aiss_user
DB_PASSWORD=your_password

# Queue (for async scan jobs)
QUEUE_CONNECTION=database
```

---

## Migration: scan_jobs table

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scan_jobs', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('target', 255);
            $table->enum('scan_type', ['full', 'quick', 'network', 'file'])->default('full');
            $table->enum('status', ['running', 'completed', 'failed'])->default('running');
            $table->integer('threats_found')->default(0);
            $table->json('findings')->nullable();
            $table->float('duration_secs')->nullable();
            $table->text('error_message')->nullable();
            $table->json('fastapi_raw_response')->nullable();  // store FastAPI JSON as-is
            $table->timestamps();

            $table->index(['user_id', 'status']);
            $table->index('created_at');
        });
    }
};
```

---

## Why Not Use Laravel at All?

If you're fully committed to Next.js + FastAPI, you don't need Laravel.
The BFF proxy (`app/api/proxy/[...path]/route.ts`) already handles:
- Clerk session validation
- Forwarding requests to FastAPI with service token
- Audit logging via X-User-Id headers

**Add Laravel when you need:**
- Complex multi-tenant authorization (Spatie Permissions)
- Eloquent ORM for business data (invoices, projects, teams)
- Artisan commands for maintenance tasks
- Laravel Horizon for Redis-backed job queues
- Sanctum for first-party SPA auth without Clerk

**Keep FastAPI for everything security-related. Always.**
