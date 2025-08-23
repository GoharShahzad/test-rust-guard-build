<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\LicenseController;

Route::post('/validate-license', [LicenseController::class, 'validateLicense']);
Route::post('/revoke-license/{licenseId}', [LicenseController::class, 'revokeLicense'])->middleware('auth:sanctum');
Route::get('/license-info', [LicenseController::class, 'getLicenseInfo'])->middleware('auth:sanctum');
Route::post('/deactivate-device', [LicenseController::class, 'deactivateDevice'])->middleware('auth:sanctum');
Route::post('/refresh-token', [LicenseController::class, 'refreshToken']);

// To-do routes
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/todos', [TodoController::class, 'index']);
    Route::post('/todos', [TodoController::class, 'store']);
    Route::put('/todos/{id}', [TodoController::class, 'update']);
    Route::delete('/todos/{id}', [TodoController::class, 'destroy']);
});