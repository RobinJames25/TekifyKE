import { Card, CardContent, CardHeader } from '@/components/ui/card';

export default function ProductLoading() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back Button Skeleton */}
      <div className="mb-6 h-9 w-32 animate-shimmer rounded-lg bg-muted" />

      <div className="grid gap-8 lg:grid-cols-2">
        {/* Image Carousel Skeleton */}
        <div className="space-y-4">
          <div className="aspect-square animate-shimmer rounded-lg bg-muted" />
          <div className="grid grid-cols-4 gap-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="aspect-square animate-shimmer rounded-lg bg-muted" />
            ))}
          </div>
        </div>

        {/* Product Info Skeleton */}
        <div className="space-y-6">
          {/* Category Badge */}
          <div className="h-7 w-24 animate-shimmer rounded-full bg-muted" />

          {/* Product Name */}
          <div className="space-y-2">
            <div className="h-10 w-full animate-shimmer rounded-lg bg-muted" />
            <div className="h-10 w-3/4 animate-shimmer rounded-lg bg-muted" />
          </div>

          {/* Price */}
          <div className="h-12 w-48 animate-shimmer rounded-lg bg-muted" />

          {/* Stock Status */}
          <div className="h-6 w-32 animate-shimmer rounded-lg bg-muted" />

          {/* Add to Cart Button */}
          <div className="h-12 w-full animate-shimmer rounded-lg bg-muted" />

          {/* Features */}
          <div className="space-y-3 border-t pt-6">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-5 w-full animate-shimmer rounded bg-muted" />
            ))}
          </div>

          {/* Description */}
          <div className="space-y-3 border-t pt-6">
            <div className="h-6 w-32 animate-shimmer rounded bg-muted" />
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-4 w-full animate-shimmer rounded bg-muted" />
              ))}
            </div>
          </div>

          {/* Specifications Card */}
          <Card>
            <CardHeader>
              <div className="h-6 w-40 animate-shimmer rounded bg-muted" />
            </CardHeader>
            <CardContent className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex justify-between border-b pb-3">
                  <div className="h-5 w-24 animate-shimmer rounded bg-muted" />
                  <div className="h-5 w-32 animate-shimmer rounded bg-muted" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Related Products Skeleton */}
      <div className="mt-16">
        <div className="mb-8 flex items-center justify-between">
          <div className="h-8 w-48 animate-shimmer rounded-lg bg-muted" />
          <div className="h-9 w-24 animate-shimmer rounded-lg bg-muted" />
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="overflow-hidden">
              <div className="aspect-square animate-shimmer bg-muted" />
              <CardHeader>
                <div className="h-5 w-full animate-shimmer rounded bg-muted" />
                <div className="h-4 w-24 animate-shimmer rounded bg-muted" />
              </CardHeader>
              <CardContent>
                <div className="h-8 w-32 animate-shimmer rounded bg-muted" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}

// Made with Bob
