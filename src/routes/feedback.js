// src/routes/feedback.js
import { Router } from 'express';

const router = Router();

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Submit feedback endpoint
router.post('/submit', async (req, res) => {
  try {
    const { name, email, component, message } = req.body;

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

    // Prepare payload for GHL webhook
    const webhookPayload = {
      name: name.trim(),
      email: email.trim(),
      component: component.trim(),
      message: message.trim(),
      timestamp: new Date().toISOString(),
      source: 'app_feedback_form'
    };

    // Forward to GHL webhook
    const response = await fetch('https://services.leadconnectorhq.com/hooks/gdzneuvA9mUJoRroCv4O/webhook-trigger/29a349e8-cc3c-4966-8f60-21b92d80d4a3', {
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