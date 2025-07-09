// server.js
require('dotenv').config();

const express = require('express');
const expressListEndpoints = require('express-list-endpoints');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const jwksClient = require('jwks-rsa'); // Required for fetching JWKS from IAS

const app = express();

// --- Configuration from Environment Variables ---
// These are CRITICAL for connecting to your SAP IAS tenant and validating tokens.
const IAS_ISSUER = process.env.IAS_ISSUER;
const IAS_JWKS_URI = process.env.IAS_JWKS_URI;
const API_AUDIENCE = process.env.API_AUDIENCE;
const PORT = process.env.PORT || 3001; // Default to port 3001

// --- Environment Variable Validation ---
// Ensure all necessary environment variables are set before starting the server.
if (!IAS_ISSUER || !IAS_JWKS_URI || !API_AUDIENCE) {
  console.error("FATAL ERROR: One or more required environment variables are missing:");
  console.error("  - IAS_ISSUER (e.g., https://<your-ias-tenant>.accounts.ondemand.com)");
  console.error("  - IAS_JWKS_URI (e.g., https://<your-ias-tenant>.accounts.ondemand.com/oauth2/certs)");
  console.error("  - API_AUDIENCE (The Client ID of your application in IAS)");
  console.error("Please set these environment variables before running the server.");
  process.exit(1); // Exit the process with an error code
}

// --- JWKS Client Setup ---
// This client fetches and caches the public keys from your IAS JWKS URI.
// These keys are used to verify the signature of JWTs issued by IAS.
const client = jwksClient({
  jwksUri: IAS_JWKS_URI,
  cache: true, // Cache the signing keys to avoid fetching on every request
  rateLimit: true, // Prevent abuse
  jwksRequestsPerMinute: 10, // Limit JWKS requests
});

// Function to get the signing key based on the 'kid' (Key ID) in the JWT header.
// This is passed to jsonwebtoken.verify for asymmetric signature verification.
function getSigningKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      console.error("Error fetching signing key from JWKS:", err);
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// --- Express Middleware ---
app.use(cors()); // Enable CORS for all origins (adjust for production if needed)
app.use(express.json()); // Parse JSON request bodies


// --- API Endpoint: /userinfo ---
/**
 * GET /userinfo
 *
 * This endpoint simulates a protected resource that requires a valid JWT
 * issued by SAP IAS for principal propagation. It verifies the token's
 * signature, issuer, audience, and expiration.
 *
 * Expected Request:
 * GET /userinfo
 * Authorization: Bearer <JWT_TOKEN_FROM_IAS>
 *
 * Response:
 * - 200 OK: If the token is valid, returns decoded user information.
 * - 401 Unauthorized: If the token is missing, malformed, expired,
 * or fails signature/issuer/audience validation.
 * - 500 Internal Server Error: For unexpected server-side issues.
 */
app.get("/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;

  // 1. Check for Authorization header and Bearer scheme
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authorization header missing or malformed (e.g., 'Bearer <token>')." });
  }

  const token = authHeader.replace("Bearer ", "");

  // 2. Define JWT verification options
  const verifyOptions = {
    algorithms: ['RS256'], // SAP IAS typically uses RS256 for asymmetric signing
    issuer: IAS_ISSUER,    // Validate the 'iss' claim against the expected IAS issuer
    audience: API_AUDIENCE, // Validate the 'aud' claim against the client ID of this API in IAS
    // You can add 'maxAge' here if needed, e.g., maxAge: '1h'
  };

  // 3. Verify the token asynchronously using the JWKS client's getSigningKey function
  jwt.verify(token, getSigningKey, verifyOptions, (err, decodedPayload) => {
    if (err) {
      // 4. Handle different types of JWT verification errors
      if (err instanceof jwt.TokenExpiredError) {
        console.warn(`JWT Error: Token expired for user (sub: ${decodedPayload?.sub || 'N/A'}).`);
        return res.status(401).json({
          message: "Token expired.",
          name: err.name,
          expiredAt: err.expiredAt,
          details: "Please obtain a new token."
        });
      }
      if (err instanceof jwt.JsonWebTokenError) {
        // This covers invalid signature, invalid issuer, invalid audience, malformed token, etc.
        console.warn(`JWT Error: Invalid token - ${err.message}.`);
        return res.status(401).json({
          message: `Invalid token: ${err.message}.`,
          name: err.name,
          details: "The token could not be verified or is not valid for this service."
        });
      }
      // Catch any other unexpected errors during verification
      console.error("Unexpected error during JWT verification:", err);
      return res.status(500).json({
        message: "Internal server error during token verification.",
        name: err.name || "UnknownError",
        details: err.message
      });
    }

    // 5. Principal Propagation Success!
    // If we reach here, the JWT is authentic, valid, not expired, and from the expected IAS issuer
    // and intended for this API audience.
    console.log(`Principal propagated successfully for user (sub): ${decodedPayload.sub}`);
    console.log(`Decoded JWT Payload: ${JSON.stringify(decodedPayload, null, 2)}`);

    // Return relevant user information from the decoded payload
    res.json({
      message: "JWT token is valid and principal propagated successfully.",
      // Extract specific claims you need for your application
      email: decodedPayload.email || decodedPayload.mail, // Use 'mail' if 'email' is not present
      userId: decodedPayload.sub, // 'sub' is the standard subject/user ID
      issuer: decodedPayload.iss, // The issuer of the token (should match IAS_ISSUER)
      // You can include other relevant claims from the payload:
      firstName: decodedPayload.firstName,
      lastName: decodedPayload.lastName,
      roles: decodedPayload.roles, // If roles are part of your JWT claims
      fullPayload: decodedPayload // Optionally return the entire payload for debugging/inspection
    });
  });
});

// --- Start the Server ---
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Expected IAS Issuer: ${IAS_ISSUER}`);
  console.log(`Expected API Audience: ${API_AUDIENCE}`);
  console.log(`JWKS URI: ${IAS_JWKS_URI}`);
  // console.log(`CORS enabled for all origins (adjust for production if needed)`);    
  // List all endpoints
  const endpoints = expressListEndpoints(app);
  console.log('Registered Endpoints:');
  endpoints.forEach(endpoint => {
    console.log(`  ${endpoint.methods.join(', ')} ${endpoint.path}`);
  });
});