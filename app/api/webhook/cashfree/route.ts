import { createClient } from '@supabase/supabase-js';
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

export async function POST(request: NextRequest) {
  try {
    // Get the request body and Cashfree signature
    const body = await request.text();
    const signature = request.headers.get('x-webhook-signature');
    
    if (!signature) {
      return NextResponse.json(
        { error: 'Missing signature header' },
        { status: 400 }
      );
    }

    // Verify signature for security
    const expectedSignature = crypto
      .createHmac('sha256', process.env.CASHFREE_SECRET_KEY!)
      .update(body)
      .digest('hex');

    if (signature !== expectedSignature) {
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 403 }
      );
    }

    // Parse the request body
    const webhookData = JSON.parse(body);
    const orderId = webhookData.data.order.order_id;
    const orderStatus = webhookData.data.order.order_status;

    // Initialize Supabase client with admin privileges
    const supabase = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      }
    );

    // Get order details from Supabase
    const { data: orderData, error: orderError } = await supabase
      .from('coin_orders')
      .select('*')
      .eq('order_id', orderId)
      .single();

    if (orderError || !orderData) {
      return NextResponse.json(
        { error: 'Order not found' },
        { status: 404 }
      );
    }

    // Update order status in Supabase
    const { error: updateError } = await supabase
      .from('coin_orders')
      .update({ status: orderStatus, updated_at: new Date().toISOString() })
      .eq('order_id', orderId);

    if (updateError) {
      console.error('Error updating order status:', updateError);
      return NextResponse.json(
        { error: 'Failed to update order status' },
        { status: 500 }
      );
    }

    // If payment is successful and status just changed to PAID, add coins to user balance
    if (orderStatus === 'PAID' && orderData.status !== 'PAID') {
      // Add transaction record
      const { error: transactionError } = await supabase
        .from('coin_transactions')
        .insert({
          user_id: orderData.user_id,
          amount: orderData.coins,
          transaction_type: 'recharge',
          description: `Purchased ${orderData.coins} coins via Cashfree (Order ID: ${orderId})`
        });

      if (transactionError) {
        console.error('Error creating transaction record:', transactionError);
        return NextResponse.json(
          { error: 'Failed to create transaction record' },
          { status: 500 }
        );
      }
    }

    // Return success response
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error in Cashfree webhook:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 