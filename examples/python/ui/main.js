const SERVICE_URL = 'http://localhost:8000'

const AUTH0_CLIENT_ID = 'SLocf7Sa1ibd5GNJMMqO539g7cKvWBOI';
const AUTH0_DOMAIN = 'auth.mozilla.auth0.com';
const AUTH0_CALLBACK_URL = window.location.href;
const SCOPES = 'openid profile email';


document.addEventListener('DOMContentLoaded', main);

function main() {
  const webAuth0 = new auth0.WebAuth({
    domain: AUTH0_DOMAIN,
    clientID: AUTH0_CLIENT_ID,
    redirectUri: AUTH0_CALLBACK_URL,
    responseType: 'token id_token',
    scope: SCOPES
  });

  // Start authentication process on Login button
  const loginBtn = document.getElementById('login');
  loginBtn.addEventListener('click', () => {
    webAuth0.authorize();
  });
  // Logout button.
  const logoutBtn = document.getElementById('logout');
  logoutBtn.addEventListener('click', logout);

  handleAuthentication(webAuth0)
}

class APIClient {
  constructor(auth) {
    const headers = {
      'Authorization': `${auth.tokenType} ${auth.accessToken}`,
    };
    this.options = {headers};
  }

  async hello() {
    const resp = await fetch(`${SERVICE_URL}/`, this.options);
    return await resp.json();
  }

  async list() {
    const resp = await fetch(`${SERVICE_URL}/records`, this.options);
    return await resp.json();
  }

  async save(name, body) {
    const resp = await fetch(`${SERVICE_URL}/records/${name}`,
                             {method: 'PUT', body, ...this.options});
    return await resp.json();
  }
}

function handleAuthentication(webAuth0) {
  let authenticated = false;

  webAuth0.parseHash((err, authResult) => {
    if (authResult && authResult.accessToken && authResult.idToken) {
      // Token was passed in location hash by authentication portal.
      authenticated = true;
      window.location.hash = '';
      setSession(authResult);
    } else if (err) {
      // Authentication returned an error.
      showError(err.errorDescription);
    } else {
      // Look into session storage for session.
      const expiresAt = JSON.parse(sessionStorage.getItem('expires_at'));
      // Check whether the current time is past the access token's expiry time
      if (new Date().getTime() < expiresAt) {
        authenticated = true;
        authResult = JSON.parse(sessionStorage.getItem('session'));
      }
    }

    // Show/hide menus.
    displayButtons(authenticated)

    // Interact with API if authenticated.
    if (authenticated) {
      console.log('AuthResult', authResult);
      showTokenPayload(authResult)

      const apiClient = new APIClient(authResult);

      initRecordForm(apiClient)

      Promise.all([
        fetchUserInfo(webAuth0, authResult),
        showAPIHello(apiClient),
        showAPIRecords(apiClient),
      ])
      .catch(showError);
    }
  });
}

function showError(err) {
  console.error(err);
  const errorDiv = document.getElementById('error');
  errorDiv.style.display = 'block';
  errorDiv.innerText = err;
}

function displayButtons(authenticated) {
  if (authenticated) {
    document.getElementById('login').setAttribute('disabled', 'disabled');
    document.getElementById('logout').removeAttribute('disabled');
    document.getElementById('view').style.display = 'block';
  } else {
    document.getElementById('login').removeAttribute('disabled');
    document.getElementById('logout').setAttribute('disabled', 'disabled');
    document.getElementById('view').style.display = 'none';
  }
}

function setSession(authResult) {
  // Set the time that the access token will expire at
  const expiresAt = JSON.stringify(
    authResult.expiresIn * 1000 + new Date().getTime()
  );
  sessionStorage.setItem('session', JSON.stringify(authResult));
  sessionStorage.setItem('expires_at', expiresAt);
}

function logout() {
  // Remove tokens and expiry time from sessionStorage
  sessionStorage.removeItem('session');
  sessionStorage.removeItem('expires_at');
  displayButtons(false);
}

async function fetchUserInfo(webAuth0, auth) {
  webAuth0.client.userInfo(auth.accessToken, (err, profile) => {
    if (err) {
      throw err;
    }
    document.getElementById('profile-nickname').innerText = profile.nickname;
    document.getElementById('profile-picture').setAttribute('src', profile.picture);
    document.getElementById('profile-details').innerText = JSON.stringify(profile, null, 2);
  });
}

function showTokenPayload(auth) {
  const tokenPayloadDiv = document.getElementById('token-payload');
  tokenPayloadDiv.innerText = JSON.stringify(auth.idTokenPayload, null, 2);
}

async function showAPIHello(apiClient) {
  const data = await apiClient.hello();

  const apiHelloDiv = document.getElementById('api-hello');
  apiHelloDiv.innerText = JSON.stringify(data, null, 2);
}

function initRecordForm(apiClient) {
  const newRecordForm = document.getElementById('api-record-form');
  // Submit data.
  newRecordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(newRecordForm);
    await apiClient.save(formData.get('name'), formData.get('data'));
    // Empty form once submitted.
    newRecordForm.reset()
    // Refresh list.
    await showAPIRecords(apiClient);
  });
}

async function showAPIRecords(apiClient) {
  const apiRecordsDiv = document.getElementById('api-records');
  apiRecordsDiv.innerHTML = '';

  const data = await apiClient.list();
  if (data.length == 0) {
    apiRecordsDiv.innerText = 'No records';
    return
  }
  for (const {name, body} of data) {
    const _name = document.createElement('h2');
    _name.innerText = name;
    const _body = document.createElement('p');
    _body.className = 'pre';
    _body.innerText = body;
    apiRecordsDiv.appendChild(_name);
    apiRecordsDiv.appendChild(_body);
  }
}
