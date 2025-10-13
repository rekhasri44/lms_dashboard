import { render, screen } from '@testing-library/react';
import App from './App';

test('renders EduAdmin dashboard', () => {
  render(<App />);
  const linkElement = screen.getByText(/EduAdmin/i);
  expect(linkElement).toBeInTheDocument();
});

test('renders without crashing', () => {
  render(<App />);
  expect(screen.getByRole('main')).toBeInTheDocument();
});