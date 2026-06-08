'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useCartStore } from '@/lib/store/cart-store';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import Image from 'next/image';
import Link from 'next/link';

interface ShippingFormData {
  fullName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  county: string;
  postalCode: string;
  additionalInfo: string;
}

interface FormErrors {
  [key: string]: string;
}

type PaymentMethod = 'PAYPAL' | 'KCB_BUNI';

export default function CheckoutPage() {
  const router = useRouter();
  const { items, getTotalPrice, clearCart } = useCartStore();
  const [mounted, setMounted] = useState(false);
  const [currentStep, setCurrentStep] = useState<1 | 2 | 3>(1);
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>('KCB_BUNI');
  const [isProcessing, setIsProcessing] = useState(false);
  const [formData, setFormData] = useState<ShippingFormData>({
    fullName: '',
    email: '',
    phone: '',
    address: '',
    city: '',
    county: 'Nairobi',
    postalCode: '',
    additionalInfo: '',
  });
  const [errors, setErrors] = useState<FormErrors>({});

  useEffect(() => {
    setMounted(true);
  }, []);

  // Redirect if cart is empty
  useEffect(() => {
    if (mounted && items.length === 0) {
      router.push('/cart');
    }
  }, [mounted, items.length, router]);

  if (!mounted) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-700 rounded w-1/4 mb-8"></div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-4">
              <div className="h-96 bg-gray-700 rounded"></div>
            </div>
            <div className="h-64 bg-gray-700 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (items.length === 0) {
    return null;
  }

  const subtotal = getTotalPrice();
  const deliveryFee = subtotal > 50000 ? 0 : 500;
  const total = subtotal + deliveryFee;

  const kenyanCounties = [
    'Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret', 'Thika', 'Malindi',
    'Kitale', 'Garissa', 'Kakamega', 'Nyeri', 'Meru', 'Kisii', 'Machakos',
    'Kiambu', 'Kajiado', 'Narok', 'Uasin Gishu', 'Trans Nzoia', 'Bungoma',
  ];

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};

    if (!formData.fullName.trim()) {
      newErrors.fullName = 'Full name is required';
    } else if (formData.fullName.trim().length < 3) {
      newErrors.fullName = 'Full name must be at least 3 characters';
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    const phoneRegex = /^(\+254|0)[17]\d{8}$/;
    if (!formData.phone.trim()) {
      newErrors.phone = 'Phone number is required';
    } else if (!phoneRegex.test(formData.phone.replace(/\s/g, ''))) {
      newErrors.phone = 'Please enter a valid Kenyan phone number (e.g., 0712345678)';
    }

    if (!formData.address.trim()) {
      newErrors.address = 'Address is required';
    } else if (formData.address.trim().length < 10) {
      newErrors.address = 'Please provide a complete address';
    }

    if (!formData.city.trim()) {
      newErrors.city = 'City is required';
    }

    if (!formData.county) {
      newErrors.county = 'County is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear error for this field
    if (errors[name]) {
      setErrors((prev) => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
  };

  const handleContinueToPayment = () => {
    if (validateForm()) {
      setCurrentStep(2);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const handleBackToShipping = () => {
    setCurrentStep(1);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleContinueToReview = () => {
    setCurrentStep(3);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBackToPayment = () => {
    setCurrentStep(2);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handlePlaceOrder = async () => {
    setIsProcessing(true);

    try {
      // Prepare order data
      const orderData = {
        shippingInfo: formData,
        paymentMethod,
        items: items.map((item) => ({
          productId: item.id,
          quantity: item.quantity,
          price: item.price,
        })),
        subtotal,
        deliveryFee,
        total,
      };

      // Call the appropriate payment API based on selected method
      if (paymentMethod === 'PAYPAL') {
        const response = await fetch('/api/payments/paypal/create-order', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(orderData),
        });

        if (!response.ok) {
          throw new Error('Failed to create PayPal order');
        }

        const data = await response.json();
        
        // Redirect to PayPal for payment
        if (data.approvalUrl) {
          window.location.href = data.approvalUrl;
        }
      } else if (paymentMethod === 'KCB_BUNI') {
        const response = await fetch('/api/payments/kcb-buni/stk-push', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(orderData),
        });

        if (!response.ok) {
          throw new Error('Failed to initiate KCB Buni payment');
        }

        const data = await response.json();
        
        // Redirect to order confirmation with pending status
        router.push(`/orders/${data.orderId}?status=pending`);
      }
    } catch (error) {
      console.error('Payment error:', error);
      alert('Failed to process payment. Please try again.');
      setIsProcessing(false);
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Progress Steps */}
      <div className="mb-8">
        <div className="flex items-center justify-center space-x-4">
          <div className="flex items-center">
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold ${
                currentStep >= 1
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-400'
              }`}
            >
              1
            </div>
            <span className="ml-2 text-sm font-medium">Shipping</span>
          </div>
          <div className="w-16 h-0.5 bg-gray-700"></div>
          <div className="flex items-center">
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold ${
                currentStep >= 2
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-400'
              }`}
            >
              2
            </div>
            <span className="ml-2 text-sm font-medium">Payment</span>
          </div>
          <div className="w-16 h-0.5 bg-gray-700"></div>
          <div className="flex items-center">
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center font-semibold ${
                currentStep >= 3
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-400'
              }`}
            >
              3
            </div>
            <span className="ml-2 text-sm font-medium">Review</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Content */}
        <div className="lg:col-span-2">
          {/* Step 1: Shipping Information */}
          {currentStep === 1 && (
            <Card className="p-6">
              <h2 className="text-2xl font-bold mb-6">Shipping Information</h2>
              <form className="space-y-4">
                <div>
                  <label htmlFor="fullName" className="block text-sm font-medium mb-2">
                    Full Name *
                  </label>
                  <input
                    type="text"
                    id="fullName"
                    name="fullName"
                    value={formData.fullName}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.fullName ? 'border-red-500' : 'border-gray-700'
                    }`}
                    placeholder="John Doe"
                  />
                  {errors.fullName && (
                    <p className="mt-1 text-sm text-red-500">{errors.fullName}</p>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium mb-2">
                      Email Address *
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        errors.email ? 'border-red-500' : 'border-gray-700'
                      }`}
                      placeholder="john@example.com"
                    />
                    {errors.email && (
                      <p className="mt-1 text-sm text-red-500">{errors.email}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="phone" className="block text-sm font-medium mb-2">
                      Phone Number *
                    </label>
                    <input
                      type="tel"
                      id="phone"
                      name="phone"
                      value={formData.phone}
                      onChange={handleInputChange}
                      className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        errors.phone ? 'border-red-500' : 'border-gray-700'
                      }`}
                      placeholder="0712345678"
                    />
                    {errors.phone && (
                      <p className="mt-1 text-sm text-red-500">{errors.phone}</p>
                    )}
                  </div>
                </div>

                <div>
                  <label htmlFor="address" className="block text-sm font-medium mb-2">
                    Street Address *
                  </label>
                  <input
                    type="text"
                    id="address"
                    name="address"
                    value={formData.address}
                    onChange={handleInputChange}
                    className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      errors.address ? 'border-red-500' : 'border-gray-700'
                    }`}
                    placeholder="123 Main Street, Apartment 4B"
                  />
                  {errors.address && (
                    <p className="mt-1 text-sm text-red-500">{errors.address}</p>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label htmlFor="city" className="block text-sm font-medium mb-2">
                      City *
                    </label>
                    <input
                      type="text"
                      id="city"
                      name="city"
                      value={formData.city}
                      onChange={handleInputChange}
                      className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        errors.city ? 'border-red-500' : 'border-gray-700'
                      }`}
                      placeholder="Nairobi"
                    />
                    {errors.city && (
                      <p className="mt-1 text-sm text-red-500">{errors.city}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="county" className="block text-sm font-medium mb-2">
                      County *
                    </label>
                    <select
                      id="county"
                      name="county"
                      value={formData.county}
                      onChange={handleInputChange}
                      className={`w-full px-4 py-2 bg-gray-800 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                        errors.county ? 'border-red-500' : 'border-gray-700'
                      }`}
                    >
                      {kenyanCounties.map((county) => (
                        <option key={county} value={county}>
                          {county}
                        </option>
                      ))}
                    </select>
                    {errors.county && (
                      <p className="mt-1 text-sm text-red-500">{errors.county}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="postalCode" className="block text-sm font-medium mb-2">
                      Postal Code
                    </label>
                    <input
                      type="text"
                      id="postalCode"
                      name="postalCode"
                      value={formData.postalCode}
                      onChange={handleInputChange}
                      className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="00100"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="additionalInfo" className="block text-sm font-medium mb-2">
                    Additional Information (Optional)
                  </label>
                  <textarea
                    id="additionalInfo"
                    name="additionalInfo"
                    value={formData.additionalInfo}
                    onChange={handleInputChange}
                    rows={3}
                    className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Delivery instructions, landmarks, etc."
                  />
                </div>

                <div className="flex justify-between pt-4">
                  <Link href="/cart">
                    <Button variant="outline">Back to Cart</Button>
                  </Link>
                  <Button onClick={handleContinueToPayment}>
                    Continue to Payment
                  </Button>
                </div>
              </form>
            </Card>
          )}

          {/* Step 2: Payment Method */}
          {currentStep === 2 && (
            <Card className="p-6">
              <h2 className="text-2xl font-bold mb-6">Payment Method</h2>
              <div className="space-y-4">
                {/* KCB Buni Option */}
                <div
                  onClick={() => setPaymentMethod('KCB_BUNI')}
                  className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                    paymentMethod === 'KCB_BUNI'
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-gray-700 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-start">
                    <input
                      type="radio"
                      name="paymentMethod"
                      checked={paymentMethod === 'KCB_BUNI'}
                      onChange={() => setPaymentMethod('KCB_BUNI')}
                      className="mt-1 mr-3"
                    />
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold text-lg">KCB Buni (M-Pesa)</h3>
                        <span className="text-xs bg-green-600 text-white px-2 py-1 rounded">
                          RECOMMENDED
                        </span>
                      </div>
                      <p className="text-sm text-gray-400 mb-3">
                        Pay securely using M-Pesa through KCB Buni. You'll receive an STK push
                        on your phone to complete the payment.
                      </p>
                      <div className="flex items-center space-x-2 text-xs text-gray-500">
                        <span>✓ Instant confirmation</span>
                        <span>•</span>
                        <span>✓ Secure</span>
                        <span>•</span>
                        <span>✓ No extra fees</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* PayPal Option */}
                <div
                  onClick={() => setPaymentMethod('PAYPAL')}
                  className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                    paymentMethod === 'PAYPAL'
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-gray-700 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-start">
                    <input
                      type="radio"
                      name="paymentMethod"
                      checked={paymentMethod === 'PAYPAL'}
                      onChange={() => setPaymentMethod('PAYPAL')}
                      className="mt-1 mr-3"
                    />
                    <div className="flex-1">
                      <h3 className="font-semibold text-lg mb-2">PayPal</h3>
                      <p className="text-sm text-gray-400 mb-3">
                        Pay with your PayPal account or credit/debit card. You'll be redirected
                        to PayPal to complete your purchase.
                      </p>
                      <div className="flex items-center space-x-2 text-xs text-gray-500">
                        <span>✓ Buyer protection</span>
                        <span>•</span>
                        <span>✓ International payments</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 mt-6">
                  <div className="flex items-start">
                    <svg
                      className="w-5 h-5 text-blue-500 mr-3 mt-0.5 flex-shrink-0"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path
                        fillRule="evenodd"
                        d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                        clipRule="evenodd"
                      />
                    </svg>
                    <div className="text-sm">
                      <p className="font-medium text-blue-400 mb-1">Secure Payment</p>
                      <p className="text-gray-400">
                        Your payment information is encrypted and secure. We never store your
                        card details.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-between pt-6">
                <Button variant="outline" onClick={handleBackToShipping}>
                  Back to Shipping
                </Button>
                <Button onClick={handleContinueToReview}>Review Order</Button>
              </div>
            </Card>
          )}

          {/* Step 3: Review Order */}
          {currentStep === 3 && (
            <div className="space-y-6">
              {/* Shipping Information Review */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold">Shipping Information</h2>
                  <Button variant="outline" size="sm" onClick={handleBackToShipping}>
                    Edit
                  </Button>
                </div>
                <div className="space-y-2 text-sm">
                  <p>
                    <span className="text-gray-400">Name:</span>{' '}
                    <span className="font-medium">{formData.fullName}</span>
                  </p>
                  <p>
                    <span className="text-gray-400">Email:</span>{' '}
                    <span className="font-medium">{formData.email}</span>
                  </p>
                  <p>
                    <span className="text-gray-400">Phone:</span>{' '}
                    <span className="font-medium">{formData.phone}</span>
                  </p>
                  <p>
                    <span className="text-gray-400">Address:</span>{' '}
                    <span className="font-medium">
                      {formData.address}, {formData.city}, {formData.county}
                      {formData.postalCode && `, ${formData.postalCode}`}
                    </span>
                  </p>
                  {formData.additionalInfo && (
                    <p>
                      <span className="text-gray-400">Notes:</span>{' '}
                      <span className="font-medium">{formData.additionalInfo}</span>
                    </p>
                  )}
                </div>
              </Card>

              {/* Payment Method Review */}
              <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold">Payment Method</h2>
                  <Button variant="outline" size="sm" onClick={handleBackToPayment}>
                    Edit
                  </Button>
                </div>
                <div className="flex items-center">
                  <div className="w-12 h-12 bg-gray-800 rounded-lg flex items-center justify-center mr-3">
                    {paymentMethod === 'KCB_BUNI' ? '📱' : '💳'}
                  </div>
                  <div>
                    <p className="font-medium">
                      {paymentMethod === 'KCB_BUNI' ? 'KCB Buni (M-Pesa)' : 'PayPal'}
                    </p>
                    <p className="text-sm text-gray-400">
                      {paymentMethod === 'KCB_BUNI'
                        ? 'You will receive an STK push to complete payment'
                        : 'You will be redirected to PayPal'}
                    </p>
                  </div>
                </div>
              </Card>

              {/* Order Items Review */}
              <Card className="p-6">
                <h2 className="text-xl font-bold mb-4">Order Items</h2>
                <div className="space-y-4">
                  {items.map((item) => (
                    <div key={item.id} className="flex items-center space-x-4">
                      <div className="relative w-16 h-16 bg-gray-800 rounded-lg overflow-hidden flex-shrink-0">
                        <Image
                          src={item.image}
                          alt={item.name}
                          fill
                          className="object-cover"
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-medium truncate">{item.name}</h3>
                        <p className="text-sm text-gray-400">Quantity: {item.quantity}</p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold">
                          KES {(item.price * item.quantity).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>

              <div className="flex justify-between pt-4">
                <Button variant="outline" onClick={handleBackToPayment}>
                  Back to Payment
                </Button>
                <Button
                  onClick={handlePlaceOrder}
                  disabled={isProcessing}
                  className="min-w-[200px]"
                >
                  {isProcessing ? (
                    <span className="flex items-center">
                      <svg
                        className="animate-spin -ml-1 mr-3 h-5 w-5 text-white"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        ></circle>
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        ></path>
                      </svg>
                      Processing...
                    </span>
                  ) : (
                    `Place Order - KES ${total.toLocaleString()}`
                  )}
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Order Summary Sidebar */}
        <div className="lg:sticky lg:top-24 h-fit">
          <Card className="p-6">
            <h2 className="text-xl font-bold mb-4">Order Summary</h2>
            <div className="space-y-3 mb-4">
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Subtotal ({items.length} items)</span>
                <span className="font-medium">KES {subtotal.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Delivery Fee</span>
                <span className="font-medium">
                  {deliveryFee === 0 ? (
                    <span className="text-green-500">FREE</span>
                  ) : (
                    `KES ${deliveryFee.toLocaleString()}`
                  )}
                </span>
              </div>
              {deliveryFee === 0 && (
                <p className="text-xs text-green-500">
                  🎉 You've qualified for free delivery!
                </p>
              )}
              {deliveryFee > 0 && subtotal > 40000 && (
                <p className="text-xs text-gray-400">
                  Add KES {(50000 - subtotal).toLocaleString()} more for free delivery
                </p>
              )}
              <div className="border-t border-gray-700 pt-3">
                <div className="flex justify-between">
                  <span className="font-semibold text-lg">Total</span>
                  <span className="font-bold text-xl text-blue-500">
                    KES {total.toLocaleString()}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4 space-y-2 text-sm">
              <div className="flex items-center text-gray-400">
                <svg
                  className="w-5 h-5 mr-2 text-green-500"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                    clipRule="evenodd"
                  />
                </svg>
                Secure checkout
              </div>
              <div className="flex items-center text-gray-400">
                <svg
                  className="w-5 h-5 mr-2 text-green-500"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                    clipRule="evenodd"
                  />
                </svg>
                {formData.county === 'Nairobi' ? '24-hour' : '2-3 day'} delivery
              </div>
              <div className="flex items-center text-gray-400">
                <svg
                  className="w-5 h-5 mr-2 text-green-500"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                    clipRule="evenodd"
                  />
                </svg>
                1-year warranty included
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Made with Bob
