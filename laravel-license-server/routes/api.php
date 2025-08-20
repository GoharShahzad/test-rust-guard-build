<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LicenseController;

Route::post('/v1/activate', [LicenseController::class,'activate']);
Route::post('/v1/heartbeat',[LicenseController::class,'heartbeat']);
Route::post('/v1/deactivate',[LicenseController::class,'deactivate']);
