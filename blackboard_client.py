import httpx
from typing import Optional, List, Dict

class BlackboardClient:
    """Client for interacting with Blackboard Learn REST API"""
    
    def __init__(self, base_url: str, app_key: str, app_secret: str):
        """
        Initialize Blackboard client.
        
        Args:
            base_url: Base URL of your Blackboard instance (e.g., https://school.blackboard.com)
            app_key: Application key from Blackboard Developer Portal
            app_secret: Application secret from Blackboard Developer Portal
        """
        self.base_url = base_url.rstrip('/')
        self.app_key = app_key
        self.app_secret = app_secret
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from Blackboard OAuth callback
            redirect_uri: The redirect URI used in the authorization request
            
        Returns:
            dict: Token response containing access_token, refresh_token, expires_in, etc.
        """
        token_url = f"{self.base_url}/learn/api/public/v1/oauth2/token"
        
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }
        
        print(f"🔄 Exchanging authorization code for token...")
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                auth=(self.app_key, self.app_secret),
                data=data,
                timeout=30.0
            )
            
            if response.status_code != 200:
                error_text = response.text
                print(f"❌ Token exchange failed: {error_text}")
                raise Exception(f"Token exchange failed (HTTP {response.status_code}): {error_text}")
            
            token_data = response.json()
            print(f"✅ Successfully obtained access token")
            return token_data
    
    async def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            dict: New token response
        """
        token_url = f"{self.base_url}/learn/api/public/v1/oauth2/token"
        
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                auth=(self.app_key, self.app_secret),
                data=data,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.text}")
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> dict:
        """
        Get information about the authenticated user.
        
        Args:
            access_token: Blackboard access token
            
        Returns:
            dict: User information
        """
        user_url = f"{self.base_url}/learn/api/public/v1/users/me"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                user_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get user info: {response.text}")
            
            return response.json()
    
    async def get_courses(self, access_token: str) -> List[dict]:
        """
        Get all courses the user is enrolled in.
        
        Args:
            access_token: Blackboard access token
            
        Returns:
            list: List of course objects
        """
        courses_url = f"{self.base_url}/learn/api/public/v1/users/me/courses"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                courses_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get courses: {response.text}")
            
            data = response.json()
            return data.get("results", [])
    
    async def get_course_details(self, course_id: str, access_token: str) -> dict:
        """
        Get details for a specific course.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            dict: Course details
        """
        course_url = f"{self.base_url}/learn/api/public/v1/courses/{course_id}"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                course_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get course details: {response.text}")
            
            return response.json()
    
    async def get_my_grades(self, course_id: str, access_token: str) -> List[dict]:
        """
        Get the user's grades for a specific course.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            list: List of grade entries
        """
        # First get the gradebook columns
        columns_url = f"{self.base_url}/learn/api/public/v2/courses/{course_id}/gradebook/columns"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            # Get columns
            columns_response = await client.get(
                columns_url,
                headers=headers,
                timeout=30.0
            )
            
            if columns_response.status_code != 200:
                raise Exception(f"Failed to get gradebook columns: {columns_response.text}")
            
            columns_data = columns_response.json()
            columns = columns_data.get("results", [])
            
            # Get grades for the user
            grades_url = f"{self.base_url}/learn/api/public/v2/courses/{course_id}/gradebook/users/me"
            
            grades_response = await client.get(
                grades_url,
                headers=headers,
                timeout=30.0
            )
            
            if grades_response.status_code != 200:
                raise Exception(f"Failed to get grades: {grades_response.text}")
            
            grades_data = grades_response.json()
            
            # Combine column info with grades
            results = []
            for column in columns:
                column_id = column.get("id")
                grade_entry = {
                    "name": column.get("name"),
                    "score": grades_data.get(column_id, {}).get("score"),
                    "text": grades_data.get(column_id, {}).get("text"),
                    "notes": grades_data.get(column_id, {}).get("notes"),
                    "feedback": grades_data.get(column_id, {}).get("feedback")
                }
                results.append(grade_entry)
            
            return results
    
    async def get_course_announcements(self, course_id: str, access_token: str) -> List[dict]:
        """
        Get announcements for a specific course.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            list: List of announcements
        """
        announcements_url = f"{self.base_url}/learn/api/public/v1/courses/{course_id}/announcements"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                announcements_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get announcements: {response.text}")
            
            data = response.json()
            return data.get("results", [])
    
    async def get_course_content(self, course_id: str, access_token: str) -> List[dict]:
        """
        Get content (folders, files, etc.) for a specific course.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            list: List of content items
        """
        content_url = f"{self.base_url}/learn/api/public/v1/courses/{course_id}/contents"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                content_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get course content: {response.text}")
            
            data = response.json()
            return data.get("results", [])
    
    async def get_course_roster(self, course_id: str, access_token: str) -> List[dict]:
        """
        Get the roster (list of users) for a course.
        Typically only available to instructors.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            list: List of users enrolled in the course
        """
        roster_url = f"{self.base_url}/learn/api/public/v1/courses/{course_id}/users"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                roster_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get course roster: {response.text}")
            
            data = response.json()
            return data.get("results", [])
    
    async def get_assignments(self, course_id: str, access_token: str) -> List[dict]:
        """
        Get assignments for a specific course.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            list: List of assignments
        """
        # Assignments are part of gradebook columns
        columns_url = f"{self.base_url}/learn/api/public/v2/courses/{course_id}/gradebook/columns"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                columns_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get assignments: {response.text}")
            
            data = response.json()
            columns = data.get("results", [])
            
            # Filter for actual assignments (exclude calculated columns)
            assignments = [
                col for col in columns 
                if col.get("grading", {}).get("type") != "Calculated"
            ]
            
            return assignments
    
    async def get_gradebook_overview(self, course_id: str, access_token: str) -> dict:
        """
        Get gradebook overview for instructors.
        
        Args:
            course_id: Blackboard course ID
            access_token: Blackboard access token
            
        Returns:
            dict: Gradebook overview data
        """
        columns_url = f"{self.base_url}/learn/api/public/v2/courses/{course_id}/gradebook/columns"
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                columns_url,
                headers=headers,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"Failed to get gradebook overview: {response.text}")
            
            return response.json()
