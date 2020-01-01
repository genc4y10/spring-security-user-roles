<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="security"
	uri="http://www.springframework.org/security/tags"%>


<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>HOME JSP PAGE</title>
</head>
<body>

	<th>HOME JSP PAGE</th>

<security:authorize access="hasRole('MANAGERS')">
	<p>
		<a href="${pageContext.request.contextPath}/leaders">LederShip</a>
	</p>
</security:authorize>

<security:authorize access="hasRole('ADMIN')">

	<p>
		<a href="${pageContext.request.contextPath}/systems">Systems</a>
	</p>
</security:authorize>


	<p>
		Kullanici adi:
		<security:authentication property="principal.username" />
		<br> Rol:
		<security:authentication property="principal.authorities" />

	</p>
	<hr>
	<form:form action="${pageContext.request.contextPath}/logout"
		method="POST">

		<input type="submit" value="CIK" />


	</form:form>


</body>
</html>