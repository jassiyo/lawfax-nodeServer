const fetchLawyer=async(req,res)=>{

      res.status(200).json({
        Heading: "jaskirat",
        data: "userDoc",
        message: "User Updated successfully",
      });
};

module.exports = {fetchLawyer};