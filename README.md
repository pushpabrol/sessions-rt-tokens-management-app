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

## Setup
1. Clone the repository and install dependencies:
   ```bash
   npm install
   ```
2. Configure environment variables in a `.env` file:
   ```
    AUTH0_DOMAIN=auth0_domain
    AUTH0_CLIENT_ID=spa client id
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

