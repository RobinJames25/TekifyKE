'use client';

import { useEffect } from 'react';
import { AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Home page error:', error);
  }, [error]);

  return (
    <div className="container mx-auto flex min-h-[60vh] items-center justify-center px-4 py-16">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-6 w-6 text-destructive" />
            <CardTitle>Something went wrong!</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            We encountered an error while loading this page. This could be a temporary issue.
          </p>
          {error.message && (
            <div className="mt-4 rounded-lg bg-destructive/10 p-3">
              <p className="text-sm font-mono text-destructive">{error.message}</p>
            </div>
          )}
        </CardContent>
        <CardFooter className="flex gap-2">
          <Button onClick={reset} className="flex-1">
            Try Again
          </Button>
          <Button variant="outline" onClick={() => window.location.href = '/'} className="flex-1">
            Go Home
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

// Made with Bob
