/* API Service Module */

class ApiService {
    constructor() {
        // Automatically determine API URL based on environment
        const isLocalDev = window.location.hostname === '127.0.0.1' ||
            window.location.hostname === 'localhost' ||
            window.location.protocol === 'file:';

        this.baseUrl = isLocalDev ? 'http://127.0.0.1:8000/api/v1' : '/api/v1';
    }

    async get(endpoint) {
        return this._request(endpoint, 'GET');
    }

    async post(endpoint, data) {
        return this._request(endpoint, 'POST', data);
    }

    async delete(endpoint) {
        return this._request(endpoint, 'DELETE');
    }

    async upload(endpoint, formData) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
            // Content-Type is auto-set by browser for FormData
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Upload Failed');
            }
            return await response.json();
        } catch (error) {
            console.error(`[API] UPLOAD ${endpoint} Failed:`, error);
            throw error;
        }
    }

    async _request(endpoint, method, data = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        };

        const config = {
            method,
            headers,
        };

        if (data) {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, config);

            // Handle 401 Unauthorized (Token Expired)
            if (response.status === 401) {
                localStorage.removeItem('access_token');
                if (!localStorage.getItem('authToken')) {
                    window.location.href = 'login.html';
                }
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || 'Unauthorized (Mock Token used?)');
            }

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'API Request Failed');
            }

            return await response.json();
        } catch (error) {
            console.error(`[API] ${method} ${endpoint} Failed:`, error);
            throw error;
        }
    }
    setToken(token) {
        localStorage.setItem('access_token', token);
    }

    getToken() {
        return localStorage.getItem('access_token');
    }

    clearToken() {
        localStorage.removeItem('access_token');
    }
}

export const apiService = new ApiService();

