'use client';

import { useEffect } from 'react';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function OrderError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Order error:', error);
  }, [error]);

  return (
    <div className="container mx-auto px-4 py-16">
      <div className="max-w-md mx-auto text-center">
        <div className="mb-6">
          <div className="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg
              className="w-10 h-10 text-red-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
          </div>
          <h1 className="text-2xl font-bold mb-2">Order Error</h1>
          <p className="text-gray-400 mb-6">
            We encountered an error while loading your order details. Please try again.
          </p>
          {error.message && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6 text-left">
              <p className="text-sm text-red-400 font-mono">{error.message}</p>
            </div>
          )}
        </div>

        <div className="space-y-3">
          <Button onClick={reset} className="w-full">
            Try Again
          </Button>
          <Link href="/products" className="block">
            <Button variant="outline" className="w-full">
              Continue Shopping
            </Button>
          </Link>
          <Link href="/" className="block">
            <Button variant="outline" className="w-full">
              Return to Home
            </Button>
          </Link>
        </div>

        <div className="mt-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <p className="text-sm text-gray-400">
            Need help? Contact our support team at{' '}
            <a href="mailto:support@tekifyke.com" className="text-blue-400 hover:underline">
              support@tekifyke.com
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
