export default function OrderLoading() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Banner Skeleton */}
      <div className="mb-8 bg-gray-800 rounded-lg p-6 animate-pulse">
        <div className="flex items-start">
          <div className="w-8 h-8 bg-gray-700 rounded-full flex-shrink-0"></div>
          <div className="ml-4 flex-1 space-y-2">
            <div className="h-6 bg-gray-700 rounded w-1/4"></div>
            <div className="h-4 bg-gray-700 rounded w-3/4"></div>
            <div className="h-3 bg-gray-700 rounded w-1/2"></div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Content Skeleton */}
        <div className="lg:col-span-2 space-y-6">
          {/* Order Status Card */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="h-8 bg-gray-700 rounded w-1/3 animate-pulse"></div>
              <div className="h-10 bg-gray-700 rounded w-24 animate-pulse"></div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="space-y-2">
                  <div className="h-3 bg-gray-700 rounded w-24 animate-pulse"></div>
                  <div className="h-4 bg-gray-700 rounded w-32 animate-pulse"></div>
                </div>
              ))}
            </div>
          </div>

          {/* Order Items Card */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="h-6 bg-gray-700 rounded w-1/4 mb-4 animate-pulse"></div>
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center space-x-4 pb-4 border-b border-gray-700">
                  <div className="w-20 h-20 bg-gray-700 rounded-lg animate-pulse"></div>
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-gray-700 rounded w-3/4 animate-pulse"></div>
                    <div className="h-3 bg-gray-700 rounded w-1/4 animate-pulse"></div>
                    <div className="h-3 bg-gray-700 rounded w-1/3 animate-pulse"></div>
                  </div>
                  <div className="h-5 bg-gray-700 rounded w-20 animate-pulse"></div>
                </div>
              ))}
            </div>
          </div>

          {/* Shipping Info Card */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="h-6 bg-gray-700 rounded w-1/3 mb-4 animate-pulse"></div>
            <div className="space-y-2">
              <div className="h-4 bg-gray-700 rounded w-full animate-pulse"></div>
              <div className="h-4 bg-gray-700 rounded w-2/3 animate-pulse"></div>
            </div>
          </div>
        </div>

        {/* Sidebar Skeleton */}
        <div className="lg:sticky lg:top-24 h-fit space-y-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="h-6 bg-gray-700 rounded w-1/2 mb-4 animate-pulse"></div>
            <div className="space-y-3 mb-4">
              <div className="flex justify-between">
                <div className="h-4 bg-gray-700 rounded w-24 animate-pulse"></div>
                <div className="h-4 bg-gray-700 rounded w-20 animate-pulse"></div>
              </div>
              <div className="flex justify-between">
                <div className="h-4 bg-gray-700 rounded w-24 animate-pulse"></div>
                <div className="h-4 bg-gray-700 rounded w-16 animate-pulse"></div>
              </div>
              <div className="border-t border-gray-700 pt-3">
                <div className="flex justify-between">
                  <div className="h-6 bg-gray-700 rounded w-16 animate-pulse"></div>
                  <div className="h-6 bg-gray-700 rounded w-24 animate-pulse"></div>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
            <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <div className="h-5 bg-gray-700 rounded w-1/2 mb-2 animate-pulse"></div>
            <div className="h-4 bg-gray-700 rounded w-full mb-3 animate-pulse"></div>
            <div className="space-y-2">
              <div className="h-4 bg-gray-700 rounded w-3/4 animate-pulse"></div>
              <div className="h-4 bg-gray-700 rounded w-2/3 animate-pulse"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
