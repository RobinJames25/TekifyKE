import Link from 'next/link';
import { Button } from '@/components/ui/button';

export default function OrderNotFound() {
  return (
    <div className="container mx-auto px-4 py-16">
      <div className="max-w-md mx-auto text-center">
        <div className="mb-6">
          <div className="w-20 h-20 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg
              className="w-10 h-10 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
          </div>
          <h1 className="text-3xl font-bold mb-2">Order Not Found</h1>
          <p className="text-gray-400 mb-6">
            We couldn't find the order you're looking for. It may have been removed or the
            link might be incorrect.
          </p>
        </div>

        <div className="space-y-3">
          <Link href="/products" className="block">
            <Button className="w-full">Continue Shopping</Button>
          </Link>
          <Link href="/" className="block">
            <Button variant="outline" className="w-full">
              Return to Home
            </Button>
          </Link>
        </div>

        <div className="mt-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <p className="text-sm text-gray-400">
            If you believe this is an error, please contact our support team at{' '}
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
