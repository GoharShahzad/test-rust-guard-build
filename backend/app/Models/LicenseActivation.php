<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class LicenseActivation extends Model
{
    use HasFactory;

    protected $fillable = [
        'license_id',
        'hardware_id',
        'device_name',
        'activated_at',
        'last_validation',
        'ip_address',
        'device_info',
        'is_active'
    ];

    protected $casts = [
        'activated_at' => 'datetime',
        'last_validation' => 'datetime',
        'device_info' => 'array',
        'is_active' => 'boolean'
    ];

    public function license(): BelongsTo
    {
        return $this->belongsTo(License::class);
    }

    public function deactivate(): void
    {
        $this->update(['is_active' => false]);
        $this->license->decrementUsedSeats();
    }
}