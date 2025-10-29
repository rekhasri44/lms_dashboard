
const ForgotPasswordPage = () => {
  return <div>Forgot Password Page - To be implemented</div>;
};

// components/NotFoundPage.jsx  
const NotFoundPage = () => {
  return <div>404 - Page Not Found</div>;
};

// components/Dashboard.jsx (Basic version)
const Dashboard = () => {
  const { user } = useAuth();
  return (
    <div>
      <h1>Welcome, {user?.name || user?.first_name}!</h1>
      <p>Dashboard content goes here...</p>
    </div>
  );
};