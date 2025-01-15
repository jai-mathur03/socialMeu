const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? 'https://your-vercel-api-url.vercel.app'  // Replace with your Vercel API URL
  : 'http://localhost:5002';

export default API_BASE_URL;
