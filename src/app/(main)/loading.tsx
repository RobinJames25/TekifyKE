import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';

export default function Loading() {
  return (
    <div className="flex flex-col">
      {/* Hero Skeleton */}
      <section className="relative overflow-hidden bg-gradient-to-br from-primary/10 via-background to-background">
        <div className="container mx-auto px-4 py-20 md:py-32">
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-8">
            <div className="flex flex-col justify-center space-y-8">
              <div className="space-y-4">
                <div className="h-16 w-3/4 animate-shimmer rounded-lg bg-muted" />
                <div className="h-6 w-full animate-shimmer rounded-lg bg-muted" />
                <div className="h-6 w-5/6 animate-shimmer rounded-lg bg-muted" />
              </div>
              <div className="flex gap-4">
                <div className="h-12 w-32 animate-shimmer rounded-lg bg-muted" />
                <div className="h-12 w-40 animate-shimmer rounded-lg bg-muted" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Skeleton */}
      <section className="border-y bg-muted/50 py-12">
        <div className="container mx-auto px-4">
          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-start space-x-4">
                <div className="h-12 w-12 animate-shimmer rounded-lg bg-muted" />
                <div className="flex-1 space-y-2">
                  <div className="h-5 w-32 animate-shimmer rounded bg-muted" />
                  <div className="h-4 w-full animate-shimmer rounded bg-muted" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Categories Skeleton */}
      <section className="py-16">
        <div className="container mx-auto px-4">
          <div className="mb-12 text-center">
            <div className="mx-auto h-10 w-64 animate-shimmer rounded-lg bg-muted" />
            <div className="mx-auto mt-4 h-6 w-96 animate-shimmer rounded-lg bg-muted" />
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-5">
            {[...Array(5)].map((_, i) => (
              <Card key={i} className="overflow-hidden">
                <div className="aspect-square animate-shimmer bg-muted" />
                <CardHeader>
                  <div className="mx-auto h-6 w-24 animate-shimmer rounded bg-muted" />
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Featured Products Skeleton */}
      <section className="bg-muted/50 py-16">
        <div className="container mx-auto px-4">
          <div className="mb-12 flex items-center justify-between">
            <div className="space-y-2">
              <div className="h-10 w-64 animate-shimmer rounded-lg bg-muted" />
              <div className="h-6 w-48 animate-shimmer rounded-lg bg-muted" />
            </div>
            <div className="h-10 w-32 animate-shimmer rounded-lg bg-muted" />
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {[...Array(8)].map((_, i) => (
              <Card key={i} className="overflow-hidden">
                <div className="aspect-square animate-shimmer bg-muted" />
                <CardHeader>
                  <div className="h-5 w-full animate-shimmer rounded bg-muted" />
                  <div className="h-4 w-24 animate-shimmer rounded bg-muted" />
                </CardHeader>
                <CardContent>
                  <div className="h-8 w-32 animate-shimmer rounded bg-muted" />
                </CardContent>
                <CardFooter>
                  <div className="h-9 w-full animate-shimmer rounded bg-muted" />
                </CardFooter>
              </Card>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

// Made with Bob
