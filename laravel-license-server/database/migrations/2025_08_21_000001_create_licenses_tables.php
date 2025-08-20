<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('licenses', function (Blueprint $t) {
            $t->id();
            $t->string('key')->unique();
            $t->enum('plan',['monthly','annual','trial'])->default('monthly');
            $t->unsignedInteger('seat_limit')->default(1);
            $t->timestamp('expires_at')->nullable();
            $t->boolean('revoked')->default(false);
            $t->json('meta')->nullable();
            $t->timestamps();
        });

        Schema::create('activations', function (Blueprint $t) {
            $t->id();
            $t->foreignId('license_id')->constrained()->cascadeOnDelete();
            $t->string('device_id');
            $t->string('device_name')->nullable();
            $t->string('status')->default('active');
            $t->timestamp('last_heartbeat_at')->nullable();
            $t->timestamps();
            $t->unique(['license_id','device_id']);
        });

        Schema::create('revocations', function (Blueprint $t) {
            $t->id();
            $t->foreignId('license_id')->constrained()->cascadeOnDelete();
            $t->string('device_id')->nullable();
            $t->string('reason')->nullable();
            $t->timestamps();
        });
    }

    public function down(): void {
        Schema::dropIfExists('revocations');
        Schema::dropIfExists('activations');
        Schema::dropIfExists('licenses');
    }
};
