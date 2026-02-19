
import { appRouter } from "@/server/routers";
import { db } from "@/lib/db";
import { users, accounts, transactions, sessions } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

jest.mock("@/lib/db", () => {
    const Database = require("better-sqlite3");
    const { drizzle } = require("drizzle-orm/better-sqlite3");
    const sqlite = new Database(":memory:");
    
    // Initialize Schema
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
  
  describe("Server Session Tests", () => {
    beforeEach(() => {
      const sqlite = (db as any).session.client;
      sqlite.exec("DELETE FROM sessions; DELETE FROM users;"); // Order matters
    });
  
    const createCaller = (user: any = null) => {
      return appRouter.createCaller({
        user,
        req: { headers: { cookie: "" } } as any,
        res: { setHeader: jest.fn(), set: jest.fn() } as any,
      });
    };
  
    test("TC-SEC-304: Session Invalidation", async () => {
          const caller = createCaller();
          // Signup creates first session
          const { user: user1, token: token1 } = await caller.auth.signup({
               email: "session@example.com",
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
  
          // Verify first session exists
          let session1 = await db.select().from(sessions).where(eq(sessions.token, token1)).get();
          expect(session1).toBeDefined();
  
          // Login again (simulate another device/browser)
          const { token: token2 } = await caller.auth.login({
              email: "session@example.com",
              password: "Password1!",
          });
  
          // Verify first session is GONE (invalidated)
          session1 = await db.select().from(sessions).where(eq(sessions.token, token1)).get();
          expect(session1).toBeUndefined();
  
          // Verify second session exists
          const session2 = await db.select().from(sessions).where(eq(sessions.token, token2)).get();
          expect(session2).toBeDefined();
    });
  });
