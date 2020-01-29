'use strict';
const Cookies = require('js-cookie');
const jwtDecode = require('jwt-decode');

class TokenManager {
    constructor(domain) {
        this.cookie = Cookies;
        this.domain = domain;
    }
    get token() {
        return this.cookie.get('token') || null;
    }

    setToken(token, options) {
        this.cookie.set('token', token, options);
    }

    get refreshToken() {
        return this.cookie.get('refresh') || null;
    }

    setRefreshToken(token, options) {
        this.cookie.set('refresh', token, options)
    }

    get user() {
        let user = this.cookie.get('user')
        return user ? JSON.parse(user) : null;
    }

    setUser(user, options) {
        this.cookie.set('user', user, options);
    }

    setSession(token, refresh) {
        const result = jwtDecode(token);
        const resultRefresh = jwtDecode(refresh);
        // Generate date from exp in payload token with format timestamp to date
        const expDate = new Date(result.exp * 1000);
        const expDateRefresh = new Date(resultRefresh.exp * 1000);
        // Calculate date : how many days between current date and expires date
        // Set Cookies with expires date
        const options = { expires: expDate, path: '/', domain: this.domain };
        const optionsRefresh = { expires: expDateRefresh, path: '/', domain: this.domain };
        this.setToken(token, options);
        this.setRefreshToken(refresh, optionsRefresh);
        this.setUser(result.user_claims, options);
        return {
            user: result.user_claims,
            token,
            refresh,
        };
    }

    removeSession() {
        const options = { path: '/', domain: this.domain };
        this.cookie.remove('refresh', options);
        this.cookie.remove('token', options);
        this.cookie.remove('user', options);
        return true;
    }
}

module.exports = function (domain) {
    return new TokenManager(domain);
};
