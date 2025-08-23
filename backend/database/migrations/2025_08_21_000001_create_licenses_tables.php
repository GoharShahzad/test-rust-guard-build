<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        // licenses table migration
        Schema::create('licenses', function (Blueprint $table) {
            $table->id();
            $table->string('key')->unique();
            $table->string('hardware_id')->nullable();
            $table->integer('seat_limit')->default(1);
            $table->integer('used_seats')->default(0);
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->boolean('is_revoked')->default(false);
            $table->text('revoke_reason')->nullable();
            $table->string('license_type')->default('standard');
            $table->json('metadata')->nullable();
            $table->timestamps();
        });
        
        // license_activations table migration
        Schema::create('license_activations', function (Blueprint $table) {
            $table->id();
            $table->foreignId('license_id')->constrained();
            $table->string('hardware_id');
            $table->string('device_name')->nullable();
            $table->timestamp('activated_at');
            $table->timestamp('last_validation')->nullable();
            $table->ipAddress('ip_address')->nullable();
            $table->text('device_info')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });
        
        // audit_logs table migration
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->string('event_type');
            $table->morphs('loggable');
            $table->text('description');
            $table->ipAddress('ip_address');
            $table->text('user_agent')->nullable();
            $table->timestamp('created_at');
        });
    }

    public function down(): void {
        Schema::dropIfExists('audit_logs');
        Schema::dropIfExists('license_activations');
        Schema::dropIfExists('licenses');
    }
};
