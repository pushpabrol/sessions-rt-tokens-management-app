# README for Express App: Session and Refresh Token Management

## Overview
This Express application integrates with Auth0 for authentication, providing functionalities for managing user sessions and refresh tokens. It allows for user search via email and manages their sessions, leveraging the Auth0 Management API.

## Features
- User authentication with Auth0.
- User must have a property in the app_metadata - admin: true
- Search users by email.
- List user sessions and manage (revoke) them.

## Prerequisites
- Node.js installed.
- Auth0 account and application setup.
- To login as admin the application checks for an `admin` claim in the id_token - To add this for your admin user please set a property in the user's app_metadata as

```
admin: true
```
- Additiobnally, you will need to create an **ACTION** and add it to the **post login trigger** with the following code to ensure this property gets set as a custom claim in the user's id_token as they login ( You only have to do this for the user that will login as admin and view/manage the sessions and tokens)
  
```
exports.onExecutePostLogin = async (event, api) => {
    if(event.user.app_metadata && event.user.app_metadata.admin) api.idToken.setCustomClaim("admin", event.user.app_metadata.admin); 
};

```

## Setup
1. Clone the repository and install dependencies:
   ```bash
   npm install
   ```
2. Configure environment variables in a `.env` file:
   ```
    AUTH0_DOMAIN=auth0_domain
    AUTH0_CLIENT_ID=client id
    AUTH0_CLIENT_SECRET=client secret
    AUTH0_MANAGEMENT_CLIENT_ID=mgmt client id
    AUTH0_MANAGEMENT_CLIENT_SECRET=mgmt client secret
    AUTH0_MANAGEMENT_API_AUDIENCE=https://auth0_domain/api/v2/
    SESSION_SECRET=YOUR_SESSION_SECRET
   ```

## Running the App
1. Start the server:
   ```bash
   npm start
   ```
2. Navigate to `http://localhost:3000` to access the application.

## Contributing
Contributions are welcome. Please open an issue or submit a pull request with any improvements or suggestions.

