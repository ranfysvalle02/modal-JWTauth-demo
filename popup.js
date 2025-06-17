document.addEventListener('DOMContentLoaded', () => {  
  init();  
});  
  
function init() {  
  document.getElementById('register').addEventListener('click', register);  
  document.getElementById('login').addEventListener('click', login);  
  document.getElementById('logout').addEventListener('click', logout);  
  document.getElementById('accessProtected').addEventListener('click', accessProtected);  
  
  // Check if user is logged in  
  checkLoginStatus();  
}  
  
async function checkLoginStatus() {  
  try {  
    const tokens = await getStoredTokens();  
    if (tokens) {  
      showLogoutButton();  
    } else {  
      hideLogoutButton();  
    }  
  } catch {  
    hideLogoutButton();  
  }  
}  
  
function showLogoutButton() {  
  document.getElementById('logout').classList.remove('hidden');  
}  
  
function hideLogoutButton() {  
  document.getElementById('logout').classList.add('hidden');  
}  
  
async function register() {  
  const username = document.getElementById('username').value.trim();  
  const password = document.getElementById('password').value;  
  
  if (!username || !password) {  
    setStatus('Please enter a username and password.', 'error');  
    return;  
  }  
  
  if (password.length < 8) {  
    setStatus('Password must be at least 8 characters long.', 'error');  
    return;  
  }  
  
  // Send username and password to server  
  try {  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/register', {  
      method: 'POST',  
      headers: {  
        'Content-Type': 'application/json'  
      },  
      body: JSON.stringify({  
        username: username,  
        password: password  
      })  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      localStorage.setItem('username', username);  
      setStatus('Registration successful.', 'success');  
      document.getElementById('password').value = '';  
    } else {  
      setStatus('Registration failed: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus('Registration failed: ' + error.message, 'error');  
  }  
}  
  
async function login() {  
  const username = document.getElementById('username').value.trim();  
  const password = document.getElementById('password').value;  
  
  if (!username || !password) {  
    setStatus('Please enter your username and password.', 'error');  
    return;  
  }  
  
  try {  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/authenticate', {  
      method: 'POST',  
      headers: {  
        'Content-Type': 'application/json'  
      },  
      body: JSON.stringify({  
        username: username,  
        password: password  
      })  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      // Store tokens securely  
      await storeTokens(result.access_token, result.refresh_token);  
      setStatus('Authentication successful.', 'success');  
      showLogoutButton();  
      document.getElementById('password').value = '';  
    } else {  
      setStatus('Authentication failed: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus('Authentication failed: ' + error.message, 'error');  
  }  
}  
  
async function logout() {  
  // Clear tokens and user data  
  await chrome.storage.local.remove('auth_tokens');  
  localStorage.removeItem('username');  
  setStatus('Logged out successfully.', 'success');  
  hideLogoutButton();  
}  
  
async function storeTokens(accessToken, refreshToken) {  
  const tokens = {  
    access_token: accessToken,  
    refresh_token: refreshToken,  
    access_token_expiry: getTokenExpiry(accessToken)  
  };  
  // Store tokens using storage API  
  await chrome.storage.local.set({ 'auth_tokens': tokens });  
}  
  
function getTokenExpiry(token) {  
  const payload = JSON.parse(atob(token.split('.')[1]));  
  return payload.exp * 1000; // Convert to milliseconds  
}  
  
async function getStoredTokens() {  
  return new Promise((resolve, reject) => {  
    chrome.storage.local.get('auth_tokens', (data) => {  
      if (chrome.runtime.lastError) {  
        reject(chrome.runtime.lastError);  
      } else {  
        resolve(data.auth_tokens);  
      }  
    });  
  });  
}  
  
async function getAccessToken() {  
  const tokens = await getStoredTokens();  
  
  if (!tokens) {  
    throw new Error('No tokens found. Please login.');  
  }  
  
  const currentTime = Date.now();  
  
  if (currentTime > tokens.access_token_expiry) {  
    // Access token expired, refresh it  
    const newTokens = await refreshAccessToken(tokens.refresh_token);  
    return newTokens.access_token;  
  } else {  
    return tokens.access_token;  
  }  
}  
  
async function refreshAccessToken(refreshToken) {  
  const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/refresh', {  
    method: 'POST',  
    headers: {  
      'Content-Type': 'application/json'  
    },  
    body: JSON.stringify({  
      refresh_token: refreshToken  
    })  
  });  
  
  const result = await response.json();  
  if (response.ok && result.status === 'ok') {  
    await storeTokens(result.access_token, result.refresh_token);  
    return {  
      access_token: result.access_token,  
      refresh_token: result.refresh_token  
    };  
  } else {  
    throw new Error('Failed to refresh token: ' + result.message);  
  }  
}  
  
async function accessProtected() {  
  try {  
    const accessToken = await getAccessToken();  
  
    const response = await fetch('https://ranfysvalle02--jwt-auth-api-fastapi-app.modal.run/protected', {  
      method: 'GET',  
      headers: {  
        'Authorization': 'Bearer ' + accessToken  
      }  
    });  
  
    const result = await response.json();  
    if (response.ok && result.status === 'ok') {  
      setStatus(result.message, 'success');  
    } else {  
      setStatus('Failed to access protected resource: ' + result.message, 'error');  
    }  
  } catch (error) {  
    setStatus(error.message, 'error');  
  }  
}  
  
let statusTimeout;  
function setStatus(message, type) {  
  clearTimeout(statusTimeout);  
  const statusDiv = document.getElementById('status');  
  statusDiv.textContent = message;  
  statusDiv.className = '';  
  statusDiv.classList.add(type === 'error' ? 'error' : 'success');  
  statusDiv.classList.add('show');  
  statusTimeout = setTimeout(() => {  
    statusDiv.classList.remove('show');  
  }, 5000);  
}  