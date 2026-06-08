export default function AdminLoading() {
  return (
    <div className="space-y-8">
      {/* Header Skeleton */}
      <div>
        <div className="h-8 bg-gray-700 rounded w-1/4 mb-2 animate-pulse"></div>
        <div className="h-4 bg-gray-700 rounded w-1/3 animate-pulse"></div>
      </div>

      {/* Metrics Grid Skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="h-4 bg-gray-700 rounded w-24 animate-pulse"></div>
              <div className="w-10 h-10 bg-gray-700 rounded-lg animate-pulse"></div>
            </div>
            <div className="space-y-2">
              <div className="h-8 bg-gray-700 rounded w-32 animate-pulse"></div>
              <div className="h-3 bg-gray-700 rounded w-20 animate-pulse"></div>
            </div>
          </div>
        ))}
      </div>

      {/* Content Grid Skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {[1, 2].map((i) => (
          <div key={i} className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="h-6 bg-gray-700 rounded w-32 animate-pulse"></div>
              <div className="h-4 bg-gray-700 rounded w-20 animate-pulse"></div>
            </div>
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map((j) => (
                <div key={j} className="h-20 bg-gray-700 rounded animate-pulse"></div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions Skeleton */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="h-6 bg-gray-700 rounded w-32 mb-6 animate-pulse"></div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-gray-700 rounded-lg animate-pulse"></div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Made with Bob
