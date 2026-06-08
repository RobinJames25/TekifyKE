import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';

export default function CartLoading() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header Skeleton */}
      <div className="mb-8">
        <div className="h-10 w-48 animate-shimmer rounded-lg bg-muted" />
        <div className="mt-2 h-5 w-32 animate-shimmer rounded-lg bg-muted" />
      </div>

      <div className="grid gap-8 lg:grid-cols-3">
        {/* Cart Items Skeleton */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="h-6 w-32 animate-shimmer rounded bg-muted" />
              <div className="h-9 w-24 animate-shimmer rounded bg-muted" />
            </CardHeader>
            <CardContent className="space-y-4">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex gap-4 border-b pb-4">
                  {/* Image */}
                  <div className="h-24 w-24 animate-shimmer rounded-lg bg-muted" />

                  {/* Info */}
                  <div className="flex flex-1 flex-col justify-between">
                    <div className="space-y-2">
                      <div className="h-5 w-48 animate-shimmer rounded bg-muted" />
                      <div className="h-6 w-24 animate-shimmer rounded bg-muted" />
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2">
                        <div className="h-8 w-8 animate-shimmer rounded bg-muted" />
                        <div className="h-5 w-12 animate-shimmer rounded bg-muted" />
                        <div className="h-8 w-8 animate-shimmer rounded bg-muted" />
                      </div>
                      <div className="h-9 w-24 animate-shimmer rounded bg-muted" />
                    </div>
                  </div>

                  {/* Total */}
                  <div className="h-6 w-24 animate-shimmer rounded bg-muted" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Order Summary Skeleton */}
        <div>
          <Card>
            <CardHeader>
              <div className="h-6 w-40 animate-shimmer rounded bg-muted" />
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                {[...Array(2)].map((_, i) => (
                  <div key={i} className="flex justify-between">
                    <div className="h-5 w-24 animate-shimmer rounded bg-muted" />
                    <div className="h-5 w-20 animate-shimmer rounded bg-muted" />
                  </div>
                ))}
              </div>
              <div className="border-t pt-4">
                <div className="flex justify-between">
                  <div className="h-6 w-16 animate-shimmer rounded bg-muted" />
                  <div className="h-8 w-32 animate-shimmer rounded bg-muted" />
                </div>
              </div>
              <div className="h-24 animate-shimmer rounded-lg bg-muted" />
            </CardContent>
            <CardFooter className="flex-col gap-2">
              <div className="h-12 w-full animate-shimmer rounded-lg bg-muted" />
              <div className="h-12 w-full animate-shimmer rounded-lg bg-muted" />
            </CardFooter>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
