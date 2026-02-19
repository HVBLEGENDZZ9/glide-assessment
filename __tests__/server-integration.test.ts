
import { appRouter } from "@/server/routers";
import { db } from "@/lib/db";
import { users, accounts, transactions, sessions } from "@/lib/db/schema";
import { eq, desc } from "drizzle-orm";
import { TRPCError } from "@trpc/server";

// Mock the database to use an in-memory SQLite instance
jest.mock("@/lib/db", () => {
  const Database = require("better-sqlite3");
  const { drizzle } = require("drizzle-orm/better-sqlite3");
  // We need to import schema dynamically inside the factory to avoid circular deps or module resolution issues
  // But jest.mock is hoisted, so ensure paths are correct. 
  // We can't use @/ aliases inside jest.mock factory easily without config, but try require.
  // Actually, let's use a simpler approach: mock the module completely returning a fresh DB for each test file execution?
  // No, better to initialize once and use excessive truncation.
  
  const sqlite = new Database(":memory:");
  
  // Initialize Schema (Copied from lib/db/index.ts)
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      phone_number TEXT NOT NULL,
      date_of_birth TEXT NOT NULL,
      ssn TEXT NOT NULL,
      address TEXT NOT NULL,
      city TEXT NOT NULL,
      state TEXT NOT NULL,
      zip_code TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      account_number TEXT UNIQUE NOT NULL,
      account_type TEXT NOT NULL,
      balance REAL DEFAULT 0 NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'pending' NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      processed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      token TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  const db = drizzle(sqlite);
  return {
    db,
    initDb: jest.fn(),
  };
});


describe("Server Integration Tests", () => {
  // Clear DB before each test
  beforeEach(() => {
    const sqlite = (db as any).session.client; // fallback access to underlying better-sqlite3
    sqlite.exec("DELETE FROM transactions; DELETE FROM sessions; DELETE FROM accounts; DELETE FROM users;");
  });

  const createCaller = (user: any = null) => {
    return appRouter.createCaller({
      user,
      req: { headers: { cookie: "" } } as any,
      res: { setHeader: jest.fn(), set: jest.fn() } as any,
    });
  };

  describe("Auth Router (Validation)", () => {
    test("TC-VAL-201: Email Validation (Typo detection)", async () => {
      const caller = createCaller();
      await expect(
        caller.auth.signup({
          email: "user@example.con",
          password: "Password1!",
          firstName: "John",
          lastName: "Doe",
          phoneNumber: "1234567890",
          dateOfBirth: "1990-01-01",
          ssn: "123456789",
          address: "123 Main St",
          city: "Anytown",
          state: "CA",
          zipCode: "12345",
          confirmPassword: "Password1!", 
        } as any)
      ).rejects.toThrow(/Possible email typo detected/);
    });

    test("TC-VAL-202: Age Verification (Under 18)", async () => {
      const caller = createCaller();
      // Future date
      await expect(
        caller.auth.signup({
          email: "test@example.com",
          password: "Password1!",
          firstName: "John",
          lastName: "Doe",
          phoneNumber: "1234567890",
          dateOfBirth: "2050-01-01",
          ssn: "123456789",
          address: "123 Main St",
          city: "Anytown",
          state: "CA",
          zipCode: "12345",
           confirmPassword: "Password1!", 
        } as any)
      ).rejects.toThrow(/Date of birth cannot be in the future/);

      // Under 18
      const today = new Date();
      const under18 = new Date(today.getFullYear() - 17, today.getMonth(), today.getDate()).toISOString().split('T')[0];
      
      await expect(
        caller.auth.signup({
          email: "test2@example.com",
          password: "Password1!",
          firstName: "John",
          lastName: "Doe",
          phoneNumber: "1234567890",
          dateOfBirth: under18,
          ssn: "123456789",
          address: "123 Main St",
          city: "Anytown",
          state: "CA",
          zipCode: "12345",
           confirmPassword: "Password1!", 
        } as any)
      ).rejects.toThrow(/You must be at least 18 years old/);
    });

    test("TC-VAL-203: State Code Validation", async () => {
        const caller = createCaller();
        await expect(
          caller.auth.signup({
            email: "test@example.com",
            password: "Password1!",
            firstName: "John",
            lastName: "Doe",
            phoneNumber: "1234567890",
            dateOfBirth: "1990-01-01",
            ssn: "123456789",
            address: "123 Main St",
            city: "Anytown",
            state: "XX", // Invalid
            zipCode: "12345",
             confirmPassword: "Password1!", 
          } as any)
        ).rejects.toThrow(/Please enter a valid US state code/);
    });

    test("TC-VAL-208: Password Complexity", async () => {
        const caller = createCaller();
        await expect(
          caller.auth.signup({
            email: "test@example.com",
            password: "password123", // Weak
            firstName: "John",
            lastName: "Doe",
            phoneNumber: "1234567890",
            dateOfBirth: "1990-01-01",
            ssn: "123456789",
            address: "123 Main St",
            city: "Anytown",
            state: "CA",
            zipCode: "12345",
             confirmPassword: "password123", 
          } as any)
        ).rejects.toThrow(/Password must contain at least one uppercase letter/);
    });
  });

  describe("Security Tests", () => {
    test("TC-SEC-301: SSN Encryption", async () => {
        const caller = createCaller();
        // Valid signup
        const result = await caller.auth.signup({
            email: "secure@example.com",
            password: "Password1!",
            firstName: "John",
            lastName: "Doe",
            phoneNumber: "1234567890",
            dateOfBirth: "1990-01-01",
            ssn: "123456789",
            address: "123 Main St",
            city: "Anytown",
            state: "CA",
            zipCode: "12345",
            confirmPassword: "Password1!", 
        } as any);

        const storedUser = await db.select().from(users).where(eq(users.id, result.user.id)).get();
        expect(storedUser).toBeDefined();
        expect(storedUser!.ssn).not.toBe("123456789");
        expect(storedUser!.ssn).toMatch(/^[0-9a-f]{32}:[0-9a-f]+$/); // IV:Encrypted
    });
  });

  describe("Account & Logic Tests", () => {
      let createdUser: any;

      beforeEach(async () => {
          const caller = createCaller();
          const { user } = await caller.auth.signup({
            email: "logic@example.com",
            password: "Password1!",
            firstName: "John",
            lastName: "Doe",
            phoneNumber: "1234567890",
            dateOfBirth: "1990-01-01",
            ssn: "123456789",
            address: "123 Main St",
            city: "Anytown",
            state: "CA",
            zipCode: "12345",
          } as any);
          createdUser = user;
      });

      test("TC-VAL-205: Zero Funding", async () => {
          const caller = createCaller(createdUser);
          const account = await caller.account.createAccount({ accountType: "checking" });

          // Zero amount
          await expect(
              caller.account.fundAccount({
                  accountId: account.id,
                  amount: 0,
                  fundingSource: { type: "card", accountNumber: "4111111111111111" }
              })
          ).rejects.toThrow(/Amount must be at least \$0.01/);

          // 0.00 amount (treated as 0 by float)
          await expect(
              caller.account.fundAccount({
                  accountId: account.id,
                  amount: 0.00,
                  fundingSource: { type: "card", accountNumber: "4111111111111111" }
              })
          ).rejects.toThrow(/Amount must be at least \$0.01/);
      });

      test("TC-PERF-406: Balance Float Precision", async () => {
          const caller = createCaller(createdUser);
          
          // Create account
          const account = await caller.account.createAccount({ accountType: "checking" });
          
          // Fund $1.05 multiple times
          for (let i = 0; i < 20; i++) {
              await caller.account.fundAccount({
                  accountId: account.id,
                  amount: 1.05,
                  fundingSource: { type: "card", accountNumber: "4111111111111111" } // Use valid prefix
              });
          }

          // Check balance - should be exactly 21.00
          // Re-fetch account
          const [updatedAccount] = await caller.account.getAccounts();
          expect(updatedAccount.balance).toBe(21.00);
      });

      test("TC-VAL-206: Card Validation (Luhn)", async () => {
           const caller = createCaller(createdUser);
           const account = await caller.account.createAccount({ accountType: "checking" });

           // Invalid Luhn
           await expect(
               caller.account.fundAccount({
                   accountId: account.id,
                   amount: 50,
                   fundingSource: { type: "card", accountNumber: "4111111111111112" } // 1 is valid, 2 should fail logic if checksum specific
               })
           ).rejects.toThrow(/Invalid card number/);
      });

      test("TC-PERF-405: Funding Transaction Retrieval (Order)", async () => {
            const caller = createCaller(createdUser);
            const account = await caller.account.createAccount({ accountType: "checking" });

            // Fund 1
            const res1 = await caller.account.fundAccount({
                accountId: account.id,
                amount: 50,
                fundingSource: { type: "card", accountNumber: "4111111111111111" }
            });
            expect(res1.transaction!.amount).toBe(50);

            // Fund 2
            const res2 = await caller.account.fundAccount({
                accountId: account.id,
                amount: 20,
                fundingSource: { type: "card", accountNumber: "4111111111111111" }
            });
            
            // Should return the NEW transaction (20), not the old one (50)
            expect(res2.transaction!.amount).toBe(20);
            expect(res2.transaction!.id).not.toBe(res1.transaction!.id);
      });
  });
});
