// src/routes/feedback.js
import { Router } from 'express';
import rateLimit from 'express-rate-limit';

const router = Router();

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Rate limiter for feedback submissions - 3 per hour per IP
const feedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 submissions per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many feedback submissions',
    message: 'You can only submit feedback 3 times per hour. Please try again later.'
  }
});

// Submit feedback endpoint
router.post('/submit', feedbackLimiter, async (req, res) => {
  console.log('📩 Feedback submission received:', {
    name: req.body?.name,
    email: req.body?.email,
    component: req.body?.component,
    otherComponent: req.body?.otherComponent,
    messageLength: req.body?.message?.length || 0
  });
  
  try {
    const { name, email, component, message, otherComponent } = req.body;

    // Validate required fields
    if (!name || !email || !component || !message) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['name', 'email', 'component', 'message']
      });
    }

    // Validate field types and content
    if (typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ error: 'Name must be a non-empty string' });
    }

    if (typeof email !== 'string' || email.trim() === '') {
      return res.status(400).json({ error: 'Email must be a non-empty string' });
    }

    if (typeof component !== 'string' || component.trim() === '') {
      return res.status(400).json({ error: 'Component must be a non-empty string' });
    }

    if (typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'Message must be a non-empty string' });
    }

    // Validate email format
    if (!emailRegex.test(email.trim())) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Determine the final component value
    const finalComponent = component === 'other' && otherComponent 
      ? otherComponent.trim() 
      : component.trim();

    // Prepare payload for GHL webhook
    const webhookPayload = {
      name: name.trim(),
      email: email.trim(),
      component: finalComponent,
      message: message.trim(),
      timestamp: new Date().toISOString(),
      source: 'app_feedback_form'
    };

    // Forward to GHL webhook
    const webhookUrl = process.env.FEEDBACK_WEBHOOK_URL;

    if (!webhookUrl) {
      console.error('FEEDBACK_WEBHOOK_URL not configured');
      return res.status(500).json({
        error: 'Feedback system not configured',
        message: 'Please contact support'
      });
    }

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(webhookPayload)
    });

    if (!response.ok) {
      console.error('GHL webhook error:', response.status, response.statusText);
      return res.status(500).json({
        error: 'Failed to submit feedback',
        details: `Webhook returned ${response.status}: ${response.statusText}`
      });
    }

    console.log('✅ Feedback successfully forwarded to GHL webhook');
    
    // Success response
    res.json({
      success: true,
      message: 'Feedback submitted successfully',
      timestamp: webhookPayload.timestamp
    });

  } catch (error) {
    console.error('Feedback submission error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to process feedback submission'
    });
  }
});

export default router;