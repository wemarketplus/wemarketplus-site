const express = require('express');
const stripe = require('stripe')('YOUR_STRIPE_SECRET_KEY');
const app = express();
app.use(express.json());

// Mapping Plan Codes to Stripe Price IDs
const PLAN_PRICE_IDS = {
    pro_0_5: 'price_123_pro',
    gold_0_10: 'price_123_gold',
    max_0_10: 'price_123_max'
};

app.post('/create-checkout-session', async (req, res) => {
    const { planCode, email } = req.body;
    
    const session = await stripe.checkout.sessions.create({
        customer_email: email,
        payment_method_types: ['card'],
        line_items: [{
            price: PLAN_PRICE_IDS[planCode],
            quantity: 1,
        }],
        mode: 'subscription',
        success_url: 'https://wemarketplus.com/success',
        cancel_url: 'https://wemarketplus.com/cancel',
    });

    res.json({ url: session.url });
});

app.listen(3000, () => console.log('Server running on port 3000'));
