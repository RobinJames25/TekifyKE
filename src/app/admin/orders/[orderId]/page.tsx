import { notFound } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { prisma } from '@/lib/prisma';

interface OrderDetailPageProps {
  params: Promise<{ orderId: string }>;
}

export default async function AdminOrderDetailPage({ params }: OrderDetailPageProps) {
  const { orderId } = await params;

  // Fetch order
  const order = await prisma.order.findUnique({
    where: { id: orderId },
    include: {
      user: {
        select: { name: true, email: true, clerkId: true },
      },
      orderItems: {
        include: {
          product: true,
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
      case 'CANCELLED':
        return 'text-red-500 bg-red-500/10 border-red-500/30';
      default:
        return 'text-gray-500 bg-gray-500/10 border-gray-500/30';
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/admin/orders"
            className="text-sm text-blue-400 hover:text-blue-300 mb-2 inline-block"
          >
            ← Back to Orders
          </Link>
          <h1 className="text-3xl font-bold text-white">Order #{order.id.slice(0, 8)}</h1>
          <p className="text-gray-400 mt-1">{formatDate(order.createdAt)}</p>
        </div>
        <div
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg border ${getStatusColor(
            order.status
          )}`}
        >
          <span className="font-semibold">{order.status}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Order Items */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Order Items</h2>
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
                      target="_blank"
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

          {/* Customer Information */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Customer Information</h2>
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-gray-400">Name</p>
                <p className="font-medium">{order.user.name || 'N/A'}</p>
              </div>
              <div>
                <p className="text-gray-400">Email</p>
                <p className="font-medium">{order.user.email}</p>
              </div>
              <div>
                <p className="text-gray-400">Phone</p>
                <p className="font-medium">{order.phoneNumber}</p>
              </div>
            </div>
          </Card>

          {/* Shipping Information */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Shipping Information</h2>
            {order.shippingAddress && typeof order.shippingAddress === 'object' && (
              <div className="space-y-2 text-sm">
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
              </div>
            )}
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Order Summary */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Order Summary</h2>
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

          {/* Payment Information */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Payment Information</h2>
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-gray-400">Payment Method</p>
                <p className="font-medium">
                  {order.paymentMethod === 'PAYPAL' ? 'PayPal' : 'KCB Buni (M-Pesa)'}
                </p>
              </div>
              {order.transactionReference && (
                <div>
                  <p className="text-gray-400">Transaction Reference</p>
                  <p className="font-medium font-mono text-xs break-all">
                    {order.transactionReference}
                  </p>
                </div>
              )}
              <div>
                <p className="text-gray-400">Payment Status</p>
                <p className={`font-medium ${order.status === 'PAID' ? 'text-green-500' : 'text-yellow-500'}`}>
                  {order.status === 'PAID' ? 'Paid' : 'Pending'}
                </p>
              </div>
            </div>
          </Card>

          {/* Status Update Actions */}
          <Card className="p-6">
            <h2 className="text-xl font-bold text-white mb-4">Update Status</h2>
            <div className="space-y-3">
              {order.status === 'PENDING' && (
                <p className="text-sm text-gray-400 mb-4">
                  Waiting for payment confirmation
                </p>
              )}
              {order.status === 'PAID' && (
                <form action={`/api/admin/orders/${order.id}/status`} method="POST">
                  <input type="hidden" name="status" value="SHIPPED" />
                  <Button type="submit" className="w-full">
                    Mark as Shipped
                  </Button>
                </form>
              )}
              {order.status === 'SHIPPED' && (
                <form action={`/api/admin/orders/${order.id}/status`} method="POST">
                  <input type="hidden" name="status" value="DELIVERED" />
                  <Button type="submit" className="w-full">
                    Mark as Delivered
                  </Button>
                </form>
              )}
              {order.status === 'DELIVERED' && (
                <p className="text-sm text-green-500 text-center">
                  ✓ Order completed
                </p>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
