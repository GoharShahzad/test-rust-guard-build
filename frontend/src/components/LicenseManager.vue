<template>
    <div class="license-manager">
      <div v-if="!isLicensed" class="activation-form">
        <h2>Activate License</h2>
        <form @submit.prevent="activateLicense">
          <div class="form-group">
            <label for="licenseKey">License Key:</label>
            <input 
              id="licenseKey" 
              v-model="licenseKey" 
              type="text" 
              placeholder="Enter your license key"
              required
            />
          </div>
          <div class="form-group">
            <label for="deviceName">Device Name:</label>
            <input 
              id="deviceName" 
              v-model="deviceName" 
              type="text" 
              placeholder="My Computer"
            />
          </div>
          <button type="submit" :disabled="activating">
            {{ activating ? 'Activating...' : 'Activate' }}
          </button>
          <p v-if="activationError" class="error">{{ activationError }}</p>
        </form>
      </div>
  
      <div v-else class="license-info">
        <h2>License Information</h2>
        <div class="license-details">
          <p><strong>Type:</strong> {{ licenseType }}</p>
          <p><strong>Seats:</strong> {{ usedSeats }} / {{ seatLimit }}</p>
          <p><strong>Status:</strong> <span :class="licenseStatusClass">{{ licenseStatus }}</span></p>
          <p><strong>Expires:</strong> {{ expirationDate }}</p>
        </div>
        
        <div v-if="activations.length > 0" class="activations">
          <h3>Active Devices</h3>
          <ul>
            <li v-for="activation in activations" :key="activation.id" class="activation-item">
              <div class="activation-info">
                <p><strong>Device:</strong> {{ activation.device_name || 'Unknown' }}</p>
                <p><strong>Hardware ID:</strong> {{ activation.hardware_id }}</p>
                <p><strong>Last Active:</strong> {{ formatDate(activation.last_validation) }}</p>
              </div>
              <button 
                v-if="canDeactivate(activation)" 
                @click="deactivateDevice(activation.id)"
                class="btn-deactivate"
              >
                Deactivate
              </button>
            </li>
          </ul>
        </div>
        
        <button @click="deactivateAll" class="btn-deactivate-all">
          Deactivate All Devices
        </button>
      </div>
    </div>
  </template>
  
  <script>
  import axios from 'axios';
  
  export default {
    name: 'LicenseManager',
    data() {
      return {
        licenseKey: '',
        deviceName: '',
        activating: false,
        activationError: '',
        licenseInfo: null,
        activations: []
      };
    },
    computed: {
      isLicensed() {
        return this.$store.state.isLicensed;
      },
      licenseType() {
        return this.licenseInfo?.license_type || 'Unknown';
      },
      seatLimit() {
        return this.licenseInfo?.seat_limit || 0;
      },
      usedSeats() {
        return this.licenseInfo?.used_seats || 0;
      },
      licenseStatus() {
        if (!this.licenseInfo) return 'Unknown';
        
        if (this.licenseInfo.is_revoked) return 'Revoked';
        if (!this.licenseInfo.is_active) return 'Inactive';
        if (this.licenseInfo.expires_at && new Date(this.licenseInfo.expires_at) < new Date()) {
          return 'Expired';
        }
        
        return 'Active';
      },
      licenseStatusClass() {
        switch (this.licenseStatus) {
          case 'Active': return 'status-active';
          case 'Expired': return 'status-expired';
          case 'Revoked': return 'status-revoked';
          default: return 'status-inactive';
        }
      },
      expirationDate() {
        return this.licenseInfo?.expires_at 
          ? new Date(this.licenseInfo.expires_at).toLocaleDateString()
          : 'Never';
      }
    },
    async mounted() {
      if (this.isLicensed) {
        await this.loadLicenseInfo();
      }
    },
    methods: {
      async activateLicense() {
        this.activating = true;
        this.activationError = '';
        
        try {
          const hardwareId = await window.electronAPI.getHardwareId();
          const deviceInfo = await this.getDeviceInfo();
          
          // Create signature
          const signature = await this.createSignature(this.licenseKey, hardwareId);
          
          const response = await axios.post(`${this.$apiBaseUrl}/api/validate-license`, {
            license_key: this.licenseKey,
            hardware_id: hardwareId,
            device_name: this.deviceName,
            device_info: deviceInfo,
            signature: signature
          });
          
          const { access_token, expires_at, license_type, seat_limit, used_seats } = response.data;
          
          // Store token
          localStorage.setItem('auth_token', access_token);
          localStorage.setItem('token_expires', expires_at);
          localStorage.setItem('license_key', this.licenseKey);
          
          this.$store.commit('setLicense', {
            isLicensed: true,
            token: access_token,
            expiresAt: expires_at,
            licenseType: license_type,
            seatLimit: seat_limit,
            usedSeats: used_seats
          });
          
          await this.loadLicenseInfo();
          
        } catch (error) {
          this.activationError = error.response?.data?.error || 'Activation failed';
          console.error('License activation error:', error);
        } finally {
          this.activating = false;
        }
      },
      
      async createSignature(licenseKey, hardwareId) {
        // In a real implementation, use proper cryptographic signing
        const data = licenseKey + hardwareId;
        const privateKey = localStorage.getItem('private_key');
        
        if (!privateKey) {
          // Generate new key pair if not exists
          const keyPair = await window.electronAPI.generateKeyPair();
          localStorage.setItem('private_key', keyPair.privateKey);
          localStorage.setItem('public_key', keyPair.publicKey);
        }
        
        return await window.electronAPI.signData(data, privateKey);
      },
      
      async loadLicenseInfo() {
        try {
          const licenseKey = localStorage.getItem('license_key');
          const response = await axios.get(`${this.$apiBaseUrl}/api/license-info`, {
            params: { license_key: licenseKey },
            headers: { Authorization: `Bearer ${this.$store.state.token}` }
          });
          
          this.licenseInfo = response.data.license;
          this.activations = response.data.activations;
        } catch (error) {
          console.error('Failed to load license info:', error);
        }
      },
      
      async deactivateDevice(activationId) {
        try {
          await axios.post(`${this.$apiBaseUrl}/api/deactivate-device`, {
            activation_id: activationId
          }, {
            headers: { Authorization: `Bearer ${this.$store.state.token}` }
          });
          
          await this.loadLicenseInfo(); // Refresh data
        } catch (error) {
          console.error('Failed to deactivate device:', error);
        }
      },
      
      async deactivateAll() {
        try {
          for (const activation of this.activations) {
            if (this.canDeactivate(activation)) {
              await this.deactivateDevice(activation.id);
            }
          }
          
          await this.loadLicenseInfo(); // Refresh data
        } catch (error) {
          console.error('Failed to deactivate all devices:', error);
        }
      },
      
      canDeactivate(activation) {
        const currentHwid = localStorage.getItem('hardware_id');
        return activation.hardware_id !== currentHwid;
      },
      
      async getDeviceInfo() {
        return {
          platform: navigator.platform,
          userAgent: navigator.userAgent,
          language: navigator.language,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          screen: {
            width: screen.width,
            height: screen.height
          }
        };
      },
      
      formatDate(dateString) {
        return new Date(dateString).toLocaleString();
      }
    }
  };
  </script>
  
  <style scoped>
  .license-manager {
    padding: 20px;
    max-width: 600px;
    margin: 0 auto;
  }
  
  .activation-form {
    background: #f5f5f5;
    padding: 20px;
    border-radius: 8px;
  }
  
  .form-group {
    margin-bottom: 15px;
  }
  
  .form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
  }
  
  .form-group input {
    width: 100%;
    padding: 8px;
    border: 1px solid #ddd;
    border-radius: 4px;
  }
  
  button {
    background: #007bff;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 4px;
    cursor: pointer;
  }
  
  button:disabled {
    background: #ccc;
    cursor: not-allowed;
  }
  
  .error {
    color: #dc3545;
    margin-top: 10px;
  }
  
  .license-info {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  }
  
  .license-details p {
    margin: 5px 0;
  }
  
  .status-active {
    color: #28a745;
  }
  
  .status-expired {
    color: #ffc107;
  }
  
  .status-revoked {
    color: #dc3545;
  }
  
  .status-inactive {
    color: #6c757d;
  }
  
  .activations {
    margin-top: 20px;
  }
  
  .activation-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px;
    border-bottom: 1px solid #eee;
  }
  
  .activation-info {
    flex: 1;
  }
  
  .btn-deactivate {
    background: #dc3545;
    padding: 5px 10px;
    font-size: 12px;
  }
  
  .btn-deactivate-all {
    background: #dc3545;
    margin-top: 20px;
  }
  </style>