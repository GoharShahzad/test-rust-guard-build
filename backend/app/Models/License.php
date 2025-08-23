<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class License extends Model
{
    use HasFactory;

    protected $fillable = [
        'key',
        'hardware_id',
        'seat_limit',
        'used_seats',
        'activated_at',
        'expires_at',
        'is_active',
        'is_revoked',
        'revoke_reason',
        'license_type',
        'metadata'
    ];

    protected $casts = [
        'activated_at' => 'datetime',
        'expires_at' => 'datetime',
        'is_active' => 'boolean',
        'is_revoked' => 'boolean',
        'metadata' => 'array'
    ];

    public function activations(): HasMany
    {
        return $this->hasMany(LicenseActivation::class);
    }

    public function isValid(): bool
    {
        return $this->is_active && 
               !$this->is_revoked &&
               $this->activated_at && 
               (!$this->expires_at || $this->expires_at->isFuture()) &&
               $this->used_seats <= $this->seat_limit;
    }

    public function canActivate(): bool
    {
        return $this->isValid() && $this->used_seats < $this->seat_limit;
    }

    public function incrementUsedSeats(): void
    {
        $this->increment('used_seats');
    }

    public function decrementUsedSeats(): void
    {
        $this->decrement('used_seats');
    }

    public function revoke(string $reason = null): void
    {
        $this->update([
            'is_revoked' => true,
            'revoke_reason' => $reason,
            'is_active' => false
        ]);
    }

    public function activate(): void
    {
        $this->update([
            'is_active' => true,
            'activated_at' => now()
        ]);
    }
}