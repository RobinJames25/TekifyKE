export default function CheckoutLoading() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Progress Steps Skeleton */}
      <div className="mb-8">
        <div className="flex items-center justify-center space-x-4">
          <div className="flex items-center">
            <div className="w-10 h-10 rounded-full bg-gray-700 animate-pulse"></div>
            <div className="ml-2 w-16 h-4 bg-gray-700 rounded animate-pulse"></div>
          </div>
          <div className="w-16 h-0.5 bg-gray-700"></div>
          <div className="flex items-center">
            <div className="w-10 h-10 rounded-full bg-gray-700 animate-pulse"></div>
            <div className="ml-2 w-16 h-4 bg-gray-700 rounded animate-pulse"></div>
          </div>
          <div className="w-16 h-0.5 bg-gray-700"></div>
          <div className="flex items-center">
            <div className="w-10 h-10 rounded-full bg-gray-700 animate-pulse"></div>
            <div className="ml-2 w-16 h-4 bg-gray-700 rounded animate-pulse"></div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Content Skeleton */}
        <div className="lg:col-span-2">
          <div className="bg-gray-800 rounded-lg p-6">
            {/* Title */}
            <div className="h-8 bg-gray-700 rounded w-1/3 mb-6 animate-pulse"></div>

            {/* Form Fields */}
            <div className="space-y-4">
              <div>
                <div className="h-4 bg-gray-700 rounded w-24 mb-2 animate-pulse"></div>
                <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="h-4 bg-gray-700 rounded w-24 mb-2 animate-pulse"></div>
                  <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
                </div>
                <div>
                  <div className="h-4 bg-gray-700 rounded w-24 mb-2 animate-pulse"></div>
                  <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
                </div>
              </div>

              <div>
                <div className="h-4 bg-gray-700 rounded w-24 mb-2 animate-pulse"></div>
                <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <div className="h-4 bg-gray-700 rounded w-16 mb-2 animate-pulse"></div>
                  <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
                </div>
                <div>
                  <div className="h-4 bg-gray-700 rounded w-16 mb-2 animate-pulse"></div>
                  <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
                </div>
                <div>
                  <div className="h-4 bg-gray-700 rounded w-20 mb-2 animate-pulse"></div>
                  <div className="h-10 bg-gray-700 rounded animate-pulse"></div>
                </div>
              </div>

              <div>
                <div className="h-4 bg-gray-700 rounded w-32 mb-2 animate-pulse"></div>
                <div className="h-24 bg-gray-700 rounded animate-pulse"></div>
              </div>
            </div>

            {/* Buttons */}
            <div className="flex justify-between pt-6">
              <div className="h-10 bg-gray-700 rounded w-32 animate-pulse"></div>
              <div className="h-10 bg-gray-700 rounded w-40 animate-pulse"></div>
            </div>
          </div>
        </div>

        {/* Sidebar Skeleton */}
        <div className="lg:sticky lg:top-24 h-fit">
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
            <div className="bg-gray-700 rounded-lg p-4 space-y-2">
              <div className="h-4 bg-gray-600 rounded animate-pulse"></div>
              <div className="h-4 bg-gray-600 rounded animate-pulse"></div>
              <div className="h-4 bg-gray-600 rounded animate-pulse"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
