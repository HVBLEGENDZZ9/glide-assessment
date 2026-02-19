import '@testing-library/jest-dom'

process.env.JWT_SECRET = "test-secret";
process.env.ENCRYPTION_KEY = "test-encryption-key-must-be-long-enough-for-hashing";

