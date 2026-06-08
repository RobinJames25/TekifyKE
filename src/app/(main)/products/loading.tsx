import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';

export default function ProductsLoading() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header Skeleton */}
      <div className="mb-8">
        <div className="h-10 w-48 animate-shimmer rounded-lg bg-muted" />
        <div className="mt-2 h-5 w-96 animate-shimmer rounded-lg bg-muted" />
      </div>

      {/* Search Bar Skeleton */}
      <div className="mb-6">
        <div className="h-12 w-full animate-shimmer rounded-lg bg-muted" />
      </div>

      <div className="grid gap-8 lg:grid-cols-[280px_1fr]">
        {/* Filters Sidebar Skeleton */}
        <aside>
          <Card className="hidden lg:block">
            <CardHeader>
              <div className="h-6 w-24 animate-shimmer rounded bg-muted" />
            </CardHeader>
            <CardContent className="space-y-6">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="space-y-3">
                  <div className="h-5 w-32 animate-shimmer rounded bg-muted" />
                  <div className="space-y-2">
                    {[...Array(3)].map((_, j) => (
                      <div
                        key={j}
                        className="h-10 w-full animate-shimmer rounded-lg bg-muted"
                      />
                    ))}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Mobile Filter Button Skeleton */}
          <div className="lg:hidden">
            <div className="h-10 w-full animate-shimmer rounded-lg bg-muted" />
          </div>
        </aside>

        {/* Products Grid Skeleton */}
        <div>
          {/* Results Count Skeleton */}
          <div className="mb-6">
            <div className="h-5 w-48 animate-shimmer rounded bg-muted" />
          </div>

          {/* Products Grid */}
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {[...Array(12)].map((_, i) => (
              <Card key={i} className="overflow-hidden">
                <div className="aspect-square animate-shimmer bg-muted" />
                <CardHeader>
                  <div className="h-5 w-full animate-shimmer rounded bg-muted" />
                  <div className="h-4 w-24 animate-shimmer rounded bg-muted" />
                </CardHeader>
                <CardContent>
                  <div className="h-8 w-32 animate-shimmer rounded bg-muted" />
                </CardContent>
                <CardFooter className="gap-2">
                  <div className="h-9 flex-1 animate-shimmer rounded bg-muted" />
                  <div className="h-9 w-9 animate-shimmer rounded bg-muted" />
                </CardFooter>
              </Card>
            ))}
          </div>

          {/* Pagination Skeleton */}
          <div className="mt-12 flex items-center justify-center gap-2">
            <div className="h-9 w-24 animate-shimmer rounded bg-muted" />
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-9 w-9 animate-shimmer rounded bg-muted" />
            ))}
            <div className="h-9 w-24 animate-shimmer rounded bg-muted" />
          </div>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
