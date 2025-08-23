<template>
    <div id="app">
      <div v-if="!authenticated" class="auth-container">
        <h1>To-Do App License Activation</h1>
        <div class="login-form">
          <input v-model="licenseKey" placeholder="Enter your license key" />
          <button @click="activateLicense">Activate License</button>
          <p v-if="error" class="error">{{ error }}</p>
        </div>
      </div>
      
      <div v-else class="todo-app">
        <header>
          <h1>Secure To-Do App</h1>
          <button @click="logout">Logout</button>
        </header>
        
        <div class="todo-container">
          <div class="add-todo">
            <input v-model="newTodo" @keyup.enter="addTodo" placeholder="Add a new task" />
            <button @click="addTodo">Add</button>
          </div>
          
          <div class="todo-list">
            <div v-for="todo in todos" :key="todo.id" class="todo-item">
              <input type="checkbox" v-model="todo.completed" @change="updateTodo(todo)" />
              <span :class="{ completed: todo.completed }">{{ todo.task }}</span>
              <button @click="deleteTodo(todo.id)">Delete</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </template>
  
  <script>
  import axios from 'axios';
  
  export default {
    name: 'App',
    data() {
      return {
        licenseKey: '',
        authenticated: false,
        error: '',
        newTodo: '',
        todos: [],
        token: null,
        refreshInterval: null
      };
    },
    async mounted() {
      // Check if we have a valid token in localStorage
      const savedToken = localStorage.getItem('auth_token');
      if (savedToken) {
        this.token = savedToken;
        this.authenticated = true;
        await this.loadTodos();
        this.setupTokenRefresh();
      }
    },
    methods: {
      async activateLicense() {
        try {
          // Get hardware ID from Rust module
          const hardwareId = await window.electronAPI.getHardwareId();
          
          // Create signature (in a real app, this would be more secure)
          const signature = await this.createSignature(this.licenseKey, hardwareId);
          
          // Validate license with server
          const response = await axios.post('http://your-laravel-app.com/api/validate-license', {
            license_key: this.licenseKey,
            hardware_id: hardwareId,
            signature: signature
          });
          
          this.token = response.data.access_token;
          localStorage.setItem('auth_token', this.token);
          this.authenticated = true;
          this.error = '';
          
          await this.loadTodos();
          this.setupTokenRefresh();
          
        } catch (error) {
          this.error = error.response?.data?.error || 'Activation failed';
        }
      },
      
      async createSignature(licenseKey, hardwareId) {
        // In a real implementation, use proper cryptographic signing
        // This is a simplified example
        const secret = 'your-secret-key'; // Should be securely stored
        const data = licenseKey + hardwareId;
        return await window.electronAPI.createLicenseToken(licenseKey, hardwareId, secret);
      },
      
      async loadTodos() {
        try {
          const response = await axios.get('http://your-laravel-app.com/api/todos', {
            headers: { Authorization: `Bearer ${this.token}` }
          });
          this.todos = response.data;
        } catch (error) {
          console.error('Failed to load todos:', error);
        }
      },
      
      async addTodo() {
        if (!this.newTodo.trim()) return;
        
        try {
          const response = await axios.post('http://your-laravel-app.com/api/todos', {
            task: this.newTodo
          }, {
            headers: { Authorization: `Bearer ${this.token}` }
          });
          
          this.todos.push(response.data);
          this.newTodo = '';
        } catch (error) {
          console.error('Failed to add todo:', error);
        }
      },
      
      async updateTodo(todo) {
        try {
          await axios.put(`http://your-laravel-app.com/api/todos/${todo.id}`, {
            completed: todo.completed
          }, {
            headers: { Authorization: `Bearer ${this.token}` }
          });
        } catch (error) {
          console.error('Failed to update todo:', error);
        }
      },
      
      async deleteTodo(id) {
        try {
          await axios.delete(`http://your-laravel-app.com/api/todos/${id}`, {
            headers: { Authorization: `Bearer ${this.token}` }
          });
          
          this.todos = this.todos.filter(todo => todo.id !== id);
        } catch (error) {
          console.error('Failed to delete todo:', error);
        }
      },
      
      logout() {
        this.authenticated = false;
        this.token = null;
        this.todos = [];
        localStorage.removeItem('auth_token');
        
        if (this.refreshInterval) {
          clearInterval(this.refreshInterval);
          this.refreshInterval = null;
        }
      },
      
      setupTokenRefresh() {
        // Refresh token every 30 minutes
        this.refreshInterval = setInterval(async () => {
          try {
            const hardwareId = await window.electronAPI.getHardwareId();
            const signature = await this.createSignature(this.licenseKey, hardwareId);
            
            const response = await axios.post('http://your-laravel-app.com/api/refresh-token', {
              license_key: this.licenseKey,
              hardware_id: hardwareId,
              signature: signature
            });
            
            this.token = response.data.access_token;
            localStorage.setItem('auth_token', this.token);
          } catch (error) {
            console.error('Token refresh failed:', error);
            this.logout();
          }
        }, 30 * 60 * 1000); // 30 minutes
      }
    }
  };
  </script>
  
  <style>
  /* Add your styles here */
  </style>