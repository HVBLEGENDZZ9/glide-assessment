import { z } from "zod";
import crypto from "crypto";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { accounts, transactions } from "@/lib/db/schema";
import { eq, and, desc } from "drizzle-orm";

// BUG-12 fix: Use cryptographically secure random number generator
function generateAccountNumber(): string {
  const bytes = crypto.randomBytes(5); // 5 bytes = 10 hex chars, plenty of entropy
  const num = parseInt(bytes.toString("hex"), 16) % 10000000000;
  return num.toString().padStart(10, "0");
}

// BUG-07 fix: Luhn algorithm for card number validation
function isValidLuhn(cardNumber: string): boolean {
  let sum = 0;
  let isEven = false;
  for (let i = cardNumber.length - 1; i >= 0; i--) {
    let digit = parseInt(cardNumber[i], 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

// BUG-07 fix: Detect card type from number with broader network support
function detectCardType(cardNumber: string): string | null {
  if (/^4\d{12}(\d{3})?$/.test(cardNumber)) return "visa";
  if (/^5[1-5]\d{14}$/.test(cardNumber)) return "mastercard";
  if (/^3[47]\d{13}$/.test(cardNumber)) return "amex";
  if (/^6(?:011|5\d{2})\d{12}$/.test(cardNumber)) return "discover";
  return null;
}

export const accountRouter = router({
  createAccount: protectedProcedure
    .input(
      z.object({
        accountType: z.enum(["checking", "savings"]),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // Check if user already has an account of this type
      const existingAccount = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.userId, ctx.user.id), eq(accounts.accountType, input.accountType)))
        .get();

      if (existingAccount) {
        throw new TRPCError({
          code: "CONFLICT",
          message: `You already have a ${input.accountType} account`,
        });
      }

      let accountNumber;
      let isUnique = false;

      // Generate unique account number
      while (!isUnique) {
        accountNumber = generateAccountNumber();
        const existing = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber)).get();
        isUnique = !existing;
      }

      await db.insert(accounts).values({
        userId: ctx.user.id,
        accountNumber: accountNumber!,
        accountType: input.accountType,
        balance: 0,
        status: "active",
      });

      // Fetch the created account
      const account = await db.select().from(accounts).where(eq(accounts.accountNumber, accountNumber!)).get();

      // BUG-16 fix: throw error instead of returning phantom $100 balance
      if (!account) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to create account. Please try again.",
        });
      }

      return account;
    }),

  getAccounts: protectedProcedure.query(async ({ ctx }) => {
    const userAccounts = await db.select().from(accounts).where(eq(accounts.userId, ctx.user.id));

    return userAccounts;
  }),

  fundAccount: protectedProcedure
    .input(
      z.object({
        accountId: z.number(),
        // BUG-06 fix: min is now 0.01, not 0
        amount: z.number().min(0.01, "Amount must be at least $0.01").max(10000, "Amount cannot exceed $10,000"),
        fundingSource: z.object({
          type: z.enum(["card", "bank"]),
          accountNumber: z.string().min(1, "Account/card number is required"),
          routingNumber: z.string().optional(),
        }),
      })
    )
    .mutation(async ({ input, ctx }) => {
      // BUG-08 fix: require routing number for bank transfers
      if (input.fundingSource.type === "bank") {
        if (!input.fundingSource.routingNumber || !/^\d{9}$/.test(input.fundingSource.routingNumber)) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "A valid 9-digit routing number is required for bank transfers",
          });
        }
      }

      // BUG-07 fix: validate card numbers with Luhn + type detection
      if (input.fundingSource.type === "card") {
        const cardNum = input.fundingSource.accountNumber;
        const cardType = detectCardType(cardNum);
        if (!cardType) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Invalid card number. We accept Visa, Mastercard, Amex, and Discover.",
          });
        }
        if (!isValidLuhn(cardNum)) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Invalid card number. Please check and try again.",
          });
        }
      }

      // Round to 2 decimal places to avoid float issues
      const amount = Math.round(input.amount * 100) / 100;

      // Verify account belongs to user
      const account = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
        .get();

      if (!account) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Account not found",
        });
      }

      if (account.status !== "active") {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Account is not active",
        });
      }

      // Create transaction
      await db.insert(transactions).values({
        accountId: input.accountId,
        type: "deposit",
        amount,
        description: `Funding from ${input.fundingSource.type}`,
        status: "completed",
        processedAt: new Date().toISOString(),
      });

      // BUG-20 fix: get the NEWEST transaction (desc order), not oldest
      const transaction = await db
        .select()
        .from(transactions)
        .where(eq(transactions.accountId, input.accountId))
        .orderBy(desc(transactions.id))
        .limit(1)
        .get();

      // BUG-21 fix: calculate balance correctly using integer arithmetic
      const newBalance = Math.round((account.balance + amount) * 100) / 100;

      // Update account balance
      await db
        .update(accounts)
        .set({
          balance: newBalance,
        })
        .where(eq(accounts.id, input.accountId));

      return {
        transaction,
        newBalance,
      };
    }),

  getTransactions: protectedProcedure
    .input(
      z.object({
        accountId: z.number(),
      })
    )
    .query(async ({ input, ctx }) => {
      // Verify account belongs to user
      const account = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.id, input.accountId), eq(accounts.userId, ctx.user.id)))
        .get();

      if (!account) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "Account not found",
        });
      }

      // BUG-19 fix: sort transactions by creation date descending (newest first)
      const accountTransactions = await db
        .select()
        .from(transactions)
        .where(eq(transactions.accountId, input.accountId))
        .orderBy(desc(transactions.createdAt));

      // BUG-22 fix: use already-fetched account data instead of N+1 queries
      const enrichedTransactions = accountTransactions.map((transaction) => ({
        ...transaction,
        accountType: account.accountType,
      }));

      return enrichedTransactions;
    }),
});
