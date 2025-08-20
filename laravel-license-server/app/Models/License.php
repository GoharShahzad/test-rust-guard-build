<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;

class License extends Model
{
    protected $fillable = ['key','plan','seat_limit','expires_at','revoked','meta'];
}
