import { prisma } from '@/lib/prisma';
import { Card } from '@/components/ui/card';
import Link from 'next/link';

interface OrdersPageProps {
  searchParams: Promise<{
    status?: string;
    search?: string;
  }>;
}

export const metadata = {
  title: 'Orders - Admin Dashboard',
  description: 'Manage orders in TekifyKE',
};

export default async function AdminOrdersPage({ searchParams }: OrdersPageProps) {
  const params = await searchParams;
  const { status, search } = params;

  // Build where clause
  const where: any = {};

  if (status && status !== 'ALL') {
    where.status = status;
  }

  if (search) {
    where.OR = [
      { id: { contains: search, mode: 'insensitive' } },
      { transactionReference: { contains: search, mode: 'insensitive' } },
      { phoneNumber: { contains: search } },
    ];
  }

  // Fetch orders
  const orders = await prisma.order.findMany({
    where,
    include: {
      user: {
        select: { name: true, email: true },
      },
      orderItems: {
        include: {
          product: {
            select: { name: true, images: true },
          },
        },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  // Get order counts by status
  const statusCounts = await prisma.order.groupBy({
    by: ['status'],
    _count: true,
  });

  const getStatusCount = (statusName: string) => {
    return statusCounts.find(s => s.status === statusName)?._count || 0;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'PAID':
        return 'bg-green-500/10 text-green-500';
      case 'PENDING':
        return 'bg-yellow-500/10 text-yellow-500';
      case 'SHIPPED':
        return 'bg-blue-500/10 text-blue-500';
      case 'DELIVERED':
        return 'bg-purple-500/10 text-purple-500';
      case 'CANCELLED':
        return 'bg-red-500/10 text-red-500';
      default:
        return 'bg-gray-500/10 text-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Orders</h1>
        <p className="text-gray-400">Manage and track customer orders</p>
      </div>

      {/* Status Tabs */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2">
        <Link
          href="/admin/orders"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
            !status || status === 'ALL'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          All Orders ({orders.length})
        </Link>
        <Link
          href="/admin/orders?status=PENDING"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
            status === 'PENDING'
              ? 'bg-yellow-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          Pending ({getStatusCount('PENDING')})
        </Link>
        <Link
          href="/admin/orders?status=PAID"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
            status === 'PAID'
              ? 'bg-green-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          Paid ({getStatusCount('PAID')})
        </Link>
        <Link
          href="/admin/orders?status=SHIPPED"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
            status === 'SHIPPED'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          Shipped ({getStatusCount('SHIPPED')})
        </Link>
        <Link
          href="/admin/orders?status=DELIVERED"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
            status === 'DELIVERED'
              ? 'bg-purple-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white'
          }`}
        >
          Delivered ({getStatusCount('DELIVERED')})
        </Link>
      </div>

      {/* Search */}
      <Card className="p-4">
        <form action="/admin/orders" method="get">
          {status && <input type="hidden" name="status" value={status} />}
          <input
            type="text"
            name="search"
            defaultValue={search}
            placeholder="Search by order ID, transaction reference, or phone number..."
            className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
          />
        </form>
      </Card>

      {/* Orders List */}
      <div className="space-y-4">
        {orders.length === 0 && (
          <Card className="p-12 text-center">
            <p className="text-gray-400">No orders found</p>
          </Card>
        )}

        {orders.map((order) => (
          <Card key={order.id} className="p-6 hover:bg-gray-800/50 transition-colors">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center space-x-3 mb-2">
                  <h3 className="text-lg font-semibold text-white">
                    Order #{order.id.slice(0, 8)}
                  </h3>
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(order.status)}`}>
                    {order.status}
                  </span>
                  <span className="px-3 py-1 rounded-full text-xs font-medium bg-gray-700 text-gray-300">
                    {order.paymentMethod === 'PAYPAL' ? 'PayPal' : 'M-Pesa'}
                  </span>
                </div>
                <div className="flex items-center space-x-4 text-sm text-gray-400">
                  <span>{order.user.name || order.user.email}</span>
                  <span>•</span>
                  <span>{order.phoneNumber}</span>
                  <span>•</span>
                  <span>
                    {new Date(order.createdAt).toLocaleDateString('en-KE', {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </span>
                </div>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold text-white">
                  KES {order.totalAmount.toLocaleString()}
                </p>
                <p className="text-sm text-gray-400">
                  {order.orderItems.length} item(s)
                </p>
              </div>
            </div>

            {/* Order Items */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mb-4">
              {order.orderItems.slice(0, 3).map((item) => (
                <div key={item.id} className="flex items-center space-x-3 p-3 bg-gray-800 rounded-lg">
                  <div className="w-12 h-12 bg-gray-700 rounded-lg overflow-hidden flex-shrink-0">
                    {item.product.images[0] && (
                      <img
                        src={item.product.images[0]}
                        alt={item.product.name}
                        className="w-full h-full object-cover"
                      />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">
                      {item.product.name}
                    </p>
                    <p className="text-xs text-gray-400">
                      Qty: {item.quantity} × KES {item.price.toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
              {order.orderItems.length > 3 && (
                <div className="flex items-center justify-center p-3 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-400">
                    +{order.orderItems.length - 3} more item(s)
                  </p>
                </div>
              )}
            </div>

            {/* Transaction Reference */}
            {order.transactionReference && (
              <div className="mb-4 p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-400 mb-1">Transaction Reference</p>
                <p className="text-sm font-mono text-white">{order.transactionReference}</p>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-between pt-4 border-t border-gray-700">
              <Link
                href={`/admin/orders/${order.id}`}
                className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
              >
                View Details →
              </Link>
              {order.status === 'PAID' && (
                <form action={`/api/admin/orders/${order.id}/status`} method="POST">
                  <input type="hidden" name="status" value="SHIPPED" />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    Mark as Shipped
                  </button>
                </form>
              )}
              {order.status === 'SHIPPED' && (
                <form action={`/api/admin/orders/${order.id}/status`} method="POST">
                  <input type="hidden" name="status" value="DELIVERED" />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    Mark as Delivered
                  </button>
                </form>
              )}
            </div>
          </Card>
        ))}
      </div>

      {/* Summary */}
      <div className="flex items-center justify-between text-sm text-gray-400">
        <p>Showing {orders.length} order(s)</p>
        <p>
          Total Revenue: KES{' '}
          {orders
            .filter(o => o.status === 'PAID' || o.status === 'SHIPPED' || o.status === 'DELIVERED')
            .reduce((sum, o) => sum + o.totalAmount, 0)
            .toLocaleString()}
        </p>
      </div>
    </div>
  );
}

// Made with Bob
