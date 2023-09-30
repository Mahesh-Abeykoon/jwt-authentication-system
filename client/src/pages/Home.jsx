import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCookies } from "react-cookie";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const Home = () => {
  const navigate = useNavigate();
  const [cookies, removeCookie] = useCookies([]);
  const [username, setUsername] = useState("");

  useEffect(() => {
    const verifyCookie = async () => {
      if (!cookies.token) {
        navigate("/login");
      }
      const { data } = await axios.post(
        "http://localhost:4000",
        {},
        { withCredentials: true }
      );
      const { status, user } = data;
      setUsername(user);

      const welcomeToastId = "welcomeToast";
      if (status && !toast.isActive(welcomeToastId)) {
        toast(`Home Page `, { toastId: welcomeToastId });
      } else if (!status) {
          removeCookie("token");
          navigate("/login");
          toast("You are logged out.");
      }
    };
    verifyCookie();
  }, [cookies, navigate, removeCookie]);

  const Logout = () => {
    removeCookie("token");
    navigate("/login");
  };

  return (
    <div className="home_page">
      <h4> Welcome <span>{username}</span> </h4>
      <button onClick={Logout}>Logout</button>
      <ToastContainer
        className="custom-toast"
        position="top-center"
        autoClose={2000}
        hideProgressBar={true}
        closeButton={false}
        rtl={false}
        pauseOnFocusLoss={false}
        draggable={false}
        pauseOnHover={false}
        theme="dark"
      />
    </div>
  );
};

export default Home;
