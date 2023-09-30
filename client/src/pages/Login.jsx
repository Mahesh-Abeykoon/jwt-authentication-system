import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';

const Login = () => {
  const navigate = useNavigate();

  const [inputValue, setInputValue] = useState({
    email: "",
    password: "",
  });

  const  {email, password}  = inputValue;

  const handleOnChange = (event) => {

    const name = event.target.name;
    const value = event.target.value;

    setInputValue({
      ...inputValue,
      [name]: value,
    });
  };

  const handleError = (err) =>
    toast.error(err);

  const handleSuccess = (msg) =>
    toast.success(msg);

  const handleSubmit = async (event) => {

    event.preventDefault();
    try {
      const { data } = await axios.post(
        "http://localhost:4000/login",
        {...inputValue,},
        { withCredentials: true });
      const { success, message } = data;
      if (success) {
        handleSuccess("Wait for Loging");
        setTimeout(() => {
          navigate("/");
        }, 1000);
      } else {
        handleError(message);
      }
    } catch (error) {
      console.log(error);
    }
    setInputValue({
      ...inputValue,
      email: "",
      password: "",
    });
  };

  return (
    <div className="form_container">
      <h2>Login Account</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="email">Email</label>
          <input
            type="email"
            name="email"
            value={email}
            placeholder="Enter your email"
            onChange={handleOnChange}
          />
        </div>
        <div>
          <label htmlFor="password">Password</label>
          <input
            type="password"
            name="password"
            value={password}
            placeholder="Enter your password"
            onChange={handleOnChange}
          />
        </div>
        <button type="submit">Submit</button>
        <span>
          Already have an account? <Link to={"/signup"}>Signup</Link>
        </span>
      </form>
        <ToastContainer
          position="top-center"
          autoClose={3000}
          hideProgressBar={false}
          newestOnTop={false}
          closeOnClick={false}
          rtl={false}
          pauseOnFocusLoss={false}
          draggable={false}
          pauseOnHover={false}
          theme="dark"
          />    
        </div>
  );
};

export default Login;