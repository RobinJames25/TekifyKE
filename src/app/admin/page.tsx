import { prisma } from '@/lib/prisma';
import { Card } from '@/components/ui/card';
import Link from 'next/link';

export const metadata = {
  title: 'Admin Dashboard - TekifyKE',
  description: 'Admin dashboard for TekifyKE e-commerce platform',
};

async function getDashboardMetrics() {
  // Get total revenue
  const paidOrders = await prisma.order.findMany({
    where: { status: 'PAID' },
    select: { totalAmount: true },
  });
  const totalRevenue = paidOrders.reduce((sum, order) => sum + order.totalAmount, 0);

  // Get order counts by status
  const orderCounts = await prisma.order.groupBy({
    by: ['status'],
    _count: true,
  });

  // Get total products and low stock products
  const totalProducts = await prisma.product.count();
  const lowStockProducts = await prisma.product.count({
    where: { stock: { lte: 10 } },
  });

  // Get recent orders
  const recentOrders = await prisma.order.findMany({
    take: 5,
    orderBy: { createdAt: 'desc' },
    include: {
      user: {
        select: { name: true, email: true },
      },
      orderItems: {
        include: {
          product: {
            select: { name: true },
          },
        },
      },
    },
  });

  // Get top selling products
  const topProducts = await prisma.orderItem.groupBy({
    by: ['productId'],
    _sum: {
      quantity: true,
    },
    orderBy: {
      _sum: {
        quantity: 'desc',
      },
    },
    take: 5,
  });

  const topProductsWithDetails = await Promise.all(
    topProducts.map(async (item) => {
      const product = await prisma.product.findUnique({
        where: { id: item.productId },
        select: { name: true, price: true, images: true },
      });
      return {
        ...product,
        totalSold: item._sum.quantity || 0,
      };
    })
  );

  // Get revenue by day for last 7 days
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const recentRevenue = await prisma.order.findMany({
    where: {
      status: 'PAID',
      createdAt: { gte: sevenDaysAgo },
    },
    select: {
      totalAmount: true,
      createdAt: true,
    },
  });

  return {
    totalRevenue,
    orderCounts,
    totalProducts,
    lowStockProducts,
    recentOrders,
    topProducts: topProductsWithDetails,
    recentRevenue,
  };
}

export default async function AdminDashboard() {
  const metrics = await getDashboardMetrics();

  const pendingOrders = metrics.orderCounts.find(o => o.status === 'PENDING')?._count || 0;
  const paidOrders = metrics.orderCounts.find(o => o.status === 'PAID')?._count || 0;
  const shippedOrders = metrics.orderCounts.find(o => o.status === 'SHIPPED')?._count || 0;
  const deliveredOrders = metrics.orderCounts.find(o => o.status === 'DELIVERED')?._count || 0;

  const totalOrders = metrics.orderCounts.reduce((sum, o) => sum + o._count, 0);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-gray-400">Welcome back! Here's what's happening with your store.</p>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Total Revenue */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-400">Total Revenue</h3>
            <div className="w-10 h-10 bg-green-500/10 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                <path d="M8.433 7.418c.155-.103.346-.196.567-.267v1.698a2.305 2.305 0 01-.567-.267C8.07 8.34 8 8.114 8 8c0-.114.07-.34.433-.582zM11 12.849v-1.698c.22.071.412.164.567.267.364.243.433.468.433.582 0 .114-.07.34-.433.582a2.305 2.305 0 01-.567.267z" />
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a1 1 0 10-2 0v.092a4.535 4.535 0 00-1.676.662C6.602 6.234 6 7.009 6 8c0 .99.602 1.765 1.324 2.246.48.32 1.054.545 1.676.662v1.941c-.391-.127-.68-.317-.843-.504a1 1 0 10-1.51 1.31c.562.649 1.413 1.076 2.353 1.253V15a1 1 0 102 0v-.092a4.535 4.535 0 001.676-.662C13.398 13.766 14 12.991 14 12c0-.99-.602-1.765-1.324-2.246A4.535 4.535 0 0011 9.092V7.151c.391.127.68.317.843.504a1 1 0 101.511-1.31c-.563-.649-1.413-1.076-2.354-1.253V5z" clipRule="evenodd" />
              </svg>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold text-white">
              KES {metrics.totalRevenue.toLocaleString()}
            </p>
            <p className="text-xs text-gray-400">From {paidOrders} paid orders</p>
          </div>
        </Card>

        {/* Total Orders */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-400">Total Orders</h3>
            <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 1a1 1 0 000 2h1.22l.305 1.222a.997.997 0 00.01.042l1.358 5.43-.893.892C3.74 11.846 4.632 14 6.414 14H15a1 1 0 000-2H6.414l1-1H14a1 1 0 00.894-.553l3-6A1 1 0 0017 3H6.28l-.31-1.243A1 1 0 005 1H3zM16 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM6.5 18a1.5 1.5 0 100-3 1.5 1.5 0 000 3z" />
              </svg>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold text-white">{totalOrders}</p>
            <p className="text-xs text-gray-400">{pendingOrders} pending</p>
          </div>
        </Card>

        {/* Total Products */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-400">Total Products</h3>
            <div className="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-purple-500" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 2a4 4 0 00-4 4v1H5a1 1 0 00-.994.89l-1 9A1 1 0 004 18h12a1 1 0 00.994-1.11l-1-9A1 1 0 0015 7h-1V6a4 4 0 00-4-4zm2 5V6a2 2 0 10-4 0v1h4zm-6 3a1 1 0 112 0 1 1 0 01-2 0zm7-1a1 1 0 100 2 1 1 0 000-2z" clipRule="evenodd" />
              </svg>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold text-white">{metrics.totalProducts}</p>
            <p className="text-xs text-gray-400">
              {metrics.lowStockProducts > 0 && (
                <span className="text-yellow-500">{metrics.lowStockProducts} low stock</span>
              )}
              {metrics.lowStockProducts === 0 && (
                <span className="text-green-500">All in stock</span>
              )}
            </p>
          </div>
        </Card>

        {/* Delivered Orders */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-400">Delivered</h3>
            <div className="w-10 h-10 bg-indigo-500/10 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-indigo-500" fill="currentColor" viewBox="0 0 20 20">
                <path d="M8 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM15 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z" />
                <path d="M3 4a1 1 0 00-1 1v10a1 1 0 001 1h1.05a2.5 2.5 0 014.9 0H10a1 1 0 001-1V5a1 1 0 00-1-1H3zM14 7a1 1 0 00-1 1v6.05A2.5 2.5 0 0115.95 16H17a1 1 0 001-1v-5a1 1 0 00-.293-.707l-2-2A1 1 0 0015 7h-1z" />
              </svg>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-2xl font-bold text-white">{deliveredOrders}</p>
            <p className="text-xs text-gray-400">{shippedOrders} in transit</p>
          </div>
        </Card>
      </div>

      {/* Recent Orders & Top Products */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Orders */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-white">Recent Orders</h2>
            <Link
              href="/admin/orders"
              className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all →
            </Link>
          </div>
          <div className="space-y-4">
            {metrics.recentOrders.length === 0 && (
              <p className="text-gray-400 text-center py-8">No orders yet</p>
            )}
            {metrics.recentOrders.map((order) => (
              <Link
                key={order.id}
                href={`/admin/orders/${order.id}`}
                className="block p-4 bg-gray-800 rounded-lg hover:bg-gray-750 transition-colors"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-white">
                    {order.user.name || order.user.email}
                  </span>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      order.status === 'PAID'
                        ? 'bg-green-500/10 text-green-500'
                        : order.status === 'PENDING'
                        ? 'bg-yellow-500/10 text-yellow-500'
                        : order.status === 'SHIPPED'
                        ? 'bg-blue-500/10 text-blue-500'
                        : 'bg-purple-500/10 text-purple-500'
                    }`}
                  >
                    {order.status}
                  </span>
                </div>
                <p className="text-sm text-gray-400 mb-2">
                  {order.orderItems.length} item(s) • KES {order.totalAmount.toLocaleString()}
                </p>
                <p className="text-xs text-gray-500">
                  {new Date(order.createdAt).toLocaleDateString('en-KE', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </p>
              </Link>
            ))}
          </div>
        </Card>

        {/* Top Products */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-white">Top Selling Products</h2>
            <Link
              href="/admin/products"
              className="text-sm text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all →
            </Link>
          </div>
          <div className="space-y-4">
            {metrics.topProducts.length === 0 && (
              <p className="text-gray-400 text-center py-8">No sales yet</p>
            )}
            {metrics.topProducts.map((product, index) => (
              <div
                key={index}
                className="flex items-center space-x-4 p-4 bg-gray-800 rounded-lg"
              >
                <div className="flex-shrink-0 w-12 h-12 bg-gray-700 rounded-lg overflow-hidden">
                  {product.images && product.images[0] && (
                    <img
                      src={product.images[0]}
                      alt={product.name || 'Product'}
                      className="w-full h-full object-cover"
                    />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    {product.name}
                  </p>
                  <p className="text-xs text-gray-400">
                    {product.totalSold} sold • KES {product.price?.toLocaleString()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="p-6">
        <h2 className="text-xl font-bold text-white mb-6">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            href="/admin/products/new"
            className="p-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors text-center"
          >
            <svg className="w-8 h-8 text-white mx-auto mb-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clipRule="evenodd" />
            </svg>
            <span className="text-white font-medium">Add Product</span>
          </Link>
          <Link
            href="/admin/orders?status=PENDING"
            className="p-4 bg-yellow-600 hover:bg-yellow-700 rounded-lg transition-colors text-center"
          >
            <svg className="w-8 h-8 text-white mx-auto mb-2" fill="currentColor" viewBox="0 0 20 20">
              <path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" />
              <path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" />
            </svg>
            <span className="text-white font-medium">Process Orders</span>
          </Link>
          <Link
            href="/admin/products?stock=low"
            className="p-4 bg-red-600 hover:bg-red-700 rounded-lg transition-colors text-center"
          >
            <svg className="w-8 h-8 text-white mx-auto mb-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span className="text-white font-medium">Low Stock Alert</span>
          </Link>
        </div>
      </Card>
    </div>
  );
}

// Made with Bob
