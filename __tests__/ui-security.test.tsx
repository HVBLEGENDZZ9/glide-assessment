
import { render, screen } from "@testing-library/react";
import { TransactionList } from "@/components/TransactionList";
import "@testing-library/jest-dom";

// Mock the trpc client
jest.mock("@/lib/trpc/client", () => ({
  trpc: {
    account: {
      getTransactions: {
        useQuery: jest.fn(),
      },
    },
  },
}));

import { trpc } from "@/lib/trpc/client";

describe("UI Security Tests", () => {
  test("TC-SEC-303: XSS in Transactions", () => {
    // Mock the query to return a malicious transaction
    (trpc.account.getTransactions.useQuery as jest.Mock).mockReturnValue({
      data: [
        {
          id: 1,
          amount: 100,
          type: "deposit",
          description: "<script>alert('xss')</script>Malicious",
          status: "completed",
          createdAt: new Date().toISOString(),
        },
      ],
      isLoading: false,
    });

    render(<TransactionList accountId={1} />);

    // Verify that the XSS payload is rendered as plain text (escaped), 
    // confirming that React is protecting against the injection.
    expect(screen.getByText("<script>alert('xss')</script>Malicious")).toBeInTheDocument();
  });
});
