import { notFound } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { prisma } from '@/lib/prisma';

interface OrderPageProps {
  params: Promise<{ orderId: string }>;
  searchParams: Promise<{ status?: string }>;
}

export default async function OrderPage({ params, searchParams }: OrderPageProps) {
  const { orderId } = await params;
  const { status } = await searchParams;

  // Fetch order from database
  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: {
      orderItems: {
        include: {
          product: true,
        },
      },
      user: {
        select: {
          name: true,
          email: true,
        },
      },
    },
  });

  if (!order) {
    notFound();
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'PAID':
        return 'text-green-500 bg-green-500/10 border-green-500/30';
      case 'PENDING':
        return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
      case 'SHIPPED':
        return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
      case 'DELIVERED':
        return 'text-purple-500 bg-purple-500/10 border-purple-500/30';
      default:
        return 'text-gray-500 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'PAID':
        return (
          <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
            <path
              fillRule="evenodd"
              d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
              clipRule="evenodd"
            />
          </svg>
        );
      case 'PENDING':
        return (
          <svg className="w-6 h-6 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            ></circle>
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            ></path>
          </svg>
        );
      case 'SHIPPED':
        return (
          <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
            <path d="M8 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM15 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
            <path d="M3 4a1 1 0 00-1 1v10a1 1 0 001 1h1.05a2.5 2.5 0 014.9 0H10a1 1 0 001-1V5a1 1 0 00-1-1H3zM14 7a1 1 0 00-1 1v6.05A2.5 2.5 0 0115.95 16H17a1 1 0 001-1v-5a1 1 0 00-.293-.707l-2-2A1 1 0 0015 7h-1z" />
          </svg>
        );
      case 'DELIVERED':
        return (
          <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
            <path d="M8 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM15 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
            <path d="M3 4a1 1 0 00-1 1v10a1 1 0 001 1h1.05a2.5 2.5 0 014.9 0H10a1 1 0 001-1V5a1 1 0 00-1-1H3zM14 7a1 1 0 00-1 1v6.05A2.5 2.5 0 0115.95 16H17a1 1 0 001-1v-5a1 1 0 00-.293-.707l-2-2A1 1 0 0015 7h-1z" />
          </svg>
        );
      default:
        return null;
    }
  };

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('en-KE', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(date));
  };

  const subtotal = order.orderItems.reduce(
    (sum: number, item) => sum + item.price * item.quantity,
    0
  );
  const deliveryFee = order.totalAmount - subtotal;

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Success Banner */}
      {order.status === 'PAID' && (
        <div className="mb-8 bg-green-500/10 border border-green-500/30 rounded-lg p-6">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg
                className="w-8 h-8 text-green-500"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
            <div className="ml-4 flex-1">
              <h2 className="text-xl font-bold text-green-400 mb-1">
                Order Confirmed!
              </h2>
              <p className="text-gray-300 mb-2">
                Thank you for your purchase. Your order has been confirmed and will be
                processed shortly.
              </p>
              <p className="text-sm text-gray-400">
                A confirmation email has been sent to{' '}
                <span className="font-medium text-gray-300">{order.user.email}</span>
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Pending Payment Banner */}
      {order.status === 'PENDING' && (
        <div className="mb-8 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg
                className="w-8 h-8 text-yellow-500 animate-pulse"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
            <div className="ml-4 flex-1">
              <h2 className="text-xl font-bold text-yellow-400 mb-1">
                Payment Pending
              </h2>
              <p className="text-gray-300 mb-2">
                {order.paymentMethod === 'KCB_BUNI'
                  ? 'Please complete the M-Pesa payment on your phone. Check your phone for the STK push notification.'
                  : 'Your payment is being processed. This page will update automatically once payment is confirmed.'}
              </p>
              <p className="text-sm text-gray-400">
                Order ID: <span className="font-medium text-gray-300">{order.id}</span>
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Order Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Order Status */}
          <Card className="p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Order Details</h2>
              <div
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg border ${getStatusColor(
                  order.status
                )}`}
              >
                {getStatusIcon(order.status)}
                <span className="font-semibold">{order.status}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-400 mb-1">Order Number</p>
                <p className="font-medium">{order.id}</p>
              </div>
              <div>
                <p className="text-gray-400 mb-1">Order Date</p>
                <p className="font-medium">{formatDate(order.createdAt)}</p>
              </div>
              <div>
                <p className="text-gray-400 mb-1">Payment Method</p>
                <p className="font-medium">
                  {order.paymentMethod === 'KCB_BUNI' ? 'KCB Buni (M-Pesa)' : 'PayPal'}
                </p>
              </div>
              {order.transactionReference && (
                <div>
                  <p className="text-gray-400 mb-1">Transaction Reference</p>
                  <p className="font-medium font-mono text-xs">
                    {order.transactionReference}
                  </p>
                </div>
              )}
            </div>
          </Card>

          {/* Order Items */}
          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">Order Items</h3>
            <div className="space-y-4">
              {order.orderItems.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center space-x-4 pb-4 border-b border-gray-700 last:border-0 last:pb-0"
                >
                  <div className="relative w-20 h-20 bg-gray-800 rounded-lg overflow-hidden flex-shrink-0">
                    <Image
                      src={item.product.images[0] || '/placeholder.png'}
                      alt={item.product.name}
                      fill
                      className="object-cover"
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <Link
                      href={`/products/${item.product.slug}`}
                      className="font-medium hover:text-blue-400 transition-colors block truncate"
                    >
                      {item.product.name}
                    </Link>
                    <p className="text-sm text-gray-400">Quantity: {item.quantity}</p>
                    <p className="text-sm text-gray-400">
                      Price: KES {item.price.toLocaleString()} each
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-semibold">
                      KES {(item.price * item.quantity).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* Shipping Information */}
          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">Shipping Information</h3>
            <div className="space-y-2 text-sm">
              {order.shippingAddress && typeof order.shippingAddress === 'object' && (
                <>
                  <p>
                    <span className="text-gray-400">Name:</span>{' '}
                    <span className="font-medium">
                      {(order.shippingAddress as any).fullName}
                    </span>
                  </p>
                  <p>
                    <span className="text-gray-400">Email:</span>{' '}
                    <span className="font-medium">
                      {(order.shippingAddress as any).email}
                    </span>
                  </p>
                  <p>
                    <span className="text-gray-400">Phone:</span>{' '}
                    <span className="font-medium">
                      {(order.shippingAddress as any).phone}
                    </span>
                  </p>
                  <p>
                    <span className="text-gray-400">Address:</span>{' '}
                    <span className="font-medium">
                      {(order.shippingAddress as any).address}
                    </span>
                  </p>
                  <p>
                    <span className="text-gray-400">City:</span>{' '}
                    <span className="font-medium">
                      {(order.shippingAddress as any).city}, {(order.shippingAddress as any).county}
                    </span>
                  </p>
                  {(order.shippingAddress as any).postalCode && (
                    <p>
                      <span className="text-gray-400">Postal Code:</span>{' '}
                      <span className="font-medium">
                        {(order.shippingAddress as any).postalCode}
                      </span>
                    </p>
                  )}
                  {(order.shippingAddress as any).additionalInfo && (
                    <p>
                      <span className="text-gray-400">Additional Info:</span>{' '}
                      <span className="font-medium">
                        {(order.shippingAddress as any).additionalInfo}
                      </span>
                    </p>
                  )}
                </>
              )}
            </div>
          </Card>
        </div>

        {/* Order Summary Sidebar */}
        <div className="lg:sticky lg:top-24 h-fit space-y-6">
          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">Order Summary</h3>
            <div className="space-y-3 mb-4">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">
                  Subtotal ({order.orderItems.length} items)
                </span>
                <span className="font-medium">KES {subtotal.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Delivery Fee</span>
                <span className="font-medium">
                  {deliveryFee === 0 ? (
                    <span className="text-green-500">FREE</span>
                  ) : (
                    `KES ${deliveryFee.toLocaleString()}`
                  )}
                </span>
              </div>
              <div className="border-t border-gray-700 pt-3">
                <div className="flex justify-between">
                  <span className="font-semibold text-lg">Total</span>
                  <span className="font-bold text-xl text-blue-500">
                    KES {order.totalAmount.toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          </Card>

          {/* Action Buttons */}
          <div className="space-y-3">
            <Link href="/products" className="block">
              <Button className="w-full">Continue Shopping</Button>
            </Link>
            <Button variant="outline" className="w-full">
              Download Invoice
            </Button>
          </div>

          {/* Help Section */}
          <Card className="p-4">
            <h4 className="font-semibold mb-2">Need Help?</h4>
            <p className="text-sm text-gray-400 mb-3">
              Contact our customer support team for any questions about your order.
            </p>
            <div className="space-y-2 text-sm">
              <a
                href="mailto:support@tekifyke.com"
                className="flex items-center text-blue-400 hover:underline"
              >
                <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z" />
                  <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z" />
                </svg>
                support@tekifyke.com
              </a>
              <a
                href="tel:+254712345678"
                className="flex items-center text-blue-400 hover:underline"
              >
                <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M2 3a1 1 0 011-1h2.153a1 1 0 01.986.836l.74 4.435a1 1 0 01-.54 1.06l-1.548.773a11.037 11.037 0 006.105 6.105l.774-1.548a1 1 0 011.059-.54l4.435.74a1 1 0 01.836.986V17a1 1 0 01-1 1h-2C7.82 18 2 12.18 2 5V3z" />
                </svg>
                +254 712 345 678
              </a>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
