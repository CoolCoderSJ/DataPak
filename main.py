from threading import Thread

from flask import Flask, request, redirect, session, render_template, send_file, Response, flash
from flask_session import Session
import os, json

from bs4 import BeautifulSoup, SoupStrainer
import requests, lxml, cchardet

app = Flask('')
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

from requests_oauthlib import OAuth2Session
import getpass
import random, string, asyncio

import os
import shutil


app.config['GITHUB_CLIENT_ID'] = os.environ['GITHUB_CLIENT_ID']
app.config['GITHUB_CLIENT_SECRET'] = os.environ['GITHUB_CLIENT_SECRET']

# Disable SSL requirement
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Settings for your app
base_discord_api_url = 'https://discordapp.com/api'
client_id = os.environ['DISCORD_CLIENT_ID'] # Get from https://discordapp.com/developers/applications
client_id.encode('unicode_escape')
client_secret = os.environ['DISCORD_CLIENT_SECRET']
redirect_uri='https://DataPak.coolcodersj.repl.co/oauth_callback'
scope = ['identify', 'email', 'connections', 'guilds', 'applications.builds.read']
token_url = 'https://discord.com/api/oauth2/token'
authorize_url = 'https://discord.com/api/oauth2/authorize'

app = Flask(__name__)
app.secret_key = os.environ['APP_SECRET_KEY'].encode('utf-8')

@app.route("/")
def home():
	if 'discord_token' not in session.keys():
		disc = ""
	else:
		discord = OAuth2Session(client_id, token=session['discord_token'])
		response = discord.get(base_discord_api_url + '/users/@me')
		disc = response.json()['username'] + "#" + response.json()['discriminator']
	if not "gh_token" in session.keys():
		gh = ""
	else:
		r = requests.get("https://api.github.com/user", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		gh = r.json()['login']
	
	if not "spotify_token" in session.keys():
		spotify = ""
	else:
		r = requests.get("https://api.spotify.com/v1/me", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		if "error" in r.json() and r.json()['error']['message'] == "The access token expired":
				spotify_client_id, spotify_client_secret = os.environ['SPOTIFY_CLIENT_ID'], os.environ['SPOTIFY_CLIENT_SECRET']
				r = requests.post("https://accounts.spotify.com/api/token", data={
					"grant_type": "refresh_token",
					"refresh_token": session['spotify_refresh_token'],
					"redirect_uri": "https://datapak.coolcodersj.repl.co/spotify/callback",
					'client_id': spotify_client_id,
					"client_secret": spotify_client_secret
				})
				session['spotify_token'] = r.json()['access_token']
				if "refresh_token" in r.json():
					session['spotify_refresh_token'] = r.json()['refresh_token']
		r = requests.get("https://api.spotify.com/v1/me", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		spotify = r.json()['display_name']

	return render_template("index.html", replitusername=request.headers['X-Replit-User-Name'], discordusername=disc, gh=gh, spotify=spotify)

@app.route('/discord')
def discord():
	oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
	login_url, state = oauth.authorization_url(authorize_url)
	session['state'] = state
	return redirect(login_url)

@app.route("/oauth_callback")
def oauth_callback():
	print(type(client_id))
	discord = OAuth2Session(client_id, redirect_uri=redirect_uri, state=session['state'], scope=scope)
	token = discord.fetch_token(
		token_url,
		client_secret=client_secret,
		authorization_response=request.url,
	)
	session['discord_token'] = token
	return redirect("/")

@app.route("/discord/generate")
def gendisc():
	if not 'discord_token' in session:
		disc = ""
		return redirect("/")
	else:
		discord = OAuth2Session(client_id, token=session['discord_token'])
		response1 = discord.get(base_discord_api_url + '/users/@me')
		response2 = discord.get(base_discord_api_url + '/users/@me/connections')
		response3 = discord.get(base_discord_api_url + '/users/@me/guilds')
		disc = {"account": response1.json(), "connections": response2.json(), "guilds": response3.json()}
		resp = Response(json.dumps(disc))
		resp.headers['Content-Type'] = 'application/json'
		return resp


@app.route('/discord/info')
def discordinfo():
	return render_template("discordinfo.html")

@app.route('/replit/info')
def replitinfo():
	return render_template("replitinfo.html")

@app.route("/replit/generate")
def replit():
	try:
		username = request.headers['X-Replit-User-Name']
		os.remove(f'DataPak{username}.zip')
	except:
		pass
	globals()['replurls'] = []
	def findrepls(r):
		global replurls
		if r.status_code == 200:
			soup = BeautifulSoup(r.content, "lxml")
			btn = soup.find_all('a', class_='jsx-688104393')
			repls = soup.find_all("a", class_='repl-item-wrapper')
			for g in repls:
				globals()['replurls'].append(str(g['href']))
			if btn != []:
				r = requests.get(f"https://replit.com{btn[0]['href']}")
				findrepls(r)
			else:
				return
	r = requests.get(f"https://replit.com/@{request.headers['X-Replit-User-Name']}")
	findrepls(r)
	username = request.headers['X-Replit-User-Name']
	os.mkdir(f"DataPak{username}")
	for repl in replurls:
		r = requests.get(f'https://replit.com{repl}.zip')
		f = open(f'DataPak{username}/{repl.split("/")[-1]}.zip', "w+")
		print(r.content, file=f)
		f.close()
	r = requests.get(f"https://replit.com/data/profiles/{request.headers['X-Replit-User-Name']}").json()
	f = open(f'DataPak{username}/account.json', "a")
	del r['repls']
	print(r, file=f)
	f.close()
	shutil.make_archive(f'DataPak{username}', 'zip', f'DataPak{username}/')
	shutil.rmtree(f'DataPak{username}/')
	return send_file(f'DataPak{username}.zip', mimetype="application/zip", as_attachment=True)
	
@app.route('/spotify/info')
def spotinfo():
	return render_template('spotifyinfo.html')

@app.route('/spotify')
def spot():
	client_id, client_secret = os.environ['SPOTIFY_CLIENT_ID'], os.environ['SPOTIFY_CLIENT_SECRET']
	scopes = [
	'user-read-recently-played',
    'user-top-read',
    'user-read-playback-position',
	'user-read-playback-state',
    'user-read-currently-playing',
	'playlist-read-private',
    'playlist-read-collaborative',
	'user-follow-read',
	'user-follow-modify',
	'user-library-read',
	'user-read-email',
    'user-read-private',
	]
	scopes = " ".join(scopes)
	if not "spotify_token" in session.keys():
		return redirect(f"https://accounts.spotify.com/authorize?response_type=code&client_id={client_id}&scope={scopes}&redirect_uri=https://datapak.coolcodersj.repl.co/spotify/callback")
	else:
		artists = requests.get("https://api.spotify.com/v1/me/following?type=artist", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		
		if artists.text == "":
			artists = {"None": "None"}
		else:
			if "message" in artists.json() and artists.json()['message'] == "The access token expired":
				client_id, client_secret = os.environ['SPOTIFY_CLIENT_ID'], os.environ['SPOTIFY_CLIENT_SECRET']
				r = requests.post("https://accounts.spotify.com/api/token", data={
					"grant_type": "refresh_token",
					"refresh_token": session['spotify_refresh_token'],
					"redirect_uri": "https://datapak.coolcodersj.repl.co/spotify/callback",
					'client_id': client_id,
					"client_secret": client_secret
				})
				session['spotify_token'] = r.json()['access_token']
				if "refresh_token" in r.json():
					session['spotify_refresh_token'] = r.json()['refresh_token']
				artists = requests.get("https://api.spotify.com/v1/me/following?type=artist", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
				})
			artists = artists.json()['artists']['items']

		albums = []
		album_req = requests.get("https://api.spotify.com/v1/me/albums", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in album_req.json()['items']:
			albums.append(item)
		while "next" in album_req.json() and album_req.json()['next'] != None:
			album_req = requests.get(album_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in album_req.json()['items']:
				albums.append(item)

		playlists = []
		playlist_req = requests.get("https://api.spotify.com/v1/me/playlists", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in playlist_req.json()['items']:
			playlists.append(item)
		while "next" in playlist_req.json() and playlist_req.json()['next'] != None:
			playlist_req = requests.get(playlist_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in playlist_req.json()['items']:
				playlists.append(item)

		liked_songs = []
		track_req = requests.get("https://api.spotify.com/v1/me/tracks", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in track_req.json()['items']:
			liked_songs.append(item)
		while "next" in track_req.json() and track_req.json()['next'] != None:
			track_req = requests.get(track_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in track_req.json()['items']:
				liked_songs.append(item)

		liked_episodes = []
		episode_req = requests.get("https://api.spotify.com/v1/me/episodes", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in episode_req.json()['items']:
			liked_episodes.append(item)
		while "next" in episode_req.json() and episode_req.json()['next'] != None:
			episode_req = requests.get(episode_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in episode_req.json()['items']:
				liked_episodes.append(item)

		shows = []
		show_req = requests.get("https://api.spotify.com/v1/me/shows", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in show_req.json()['items']:
			shows.append(item)
		while "next" in show_req.json() and show_req.json()['next'] != None:
			show_req = requests.get(show_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in show_req.json()['items']:
				shows.append(item)

		top_tracks = []
		track_req = requests.get("https://api.spotify.com/v1/me/top/tracks", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in track_req.json()['items']:
			top_tracks.append(item)
		while "next" in track_req.json() and track_req.json()['next'] != None:
			track_req = requests.get(track_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in track_req.json()['items']:
				top_tracks.append(item)

		top_artists = []
		artist_req = requests.get("https://api.spotify.com/v1/me/top/tracks", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in artist_req.json()['items']:
			top_artists.append(item)
		while "next" in artist_req.json() and artist_req.json()['next'] != None:
			artist_req = requests.get(artist_req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in artist_req.json()['items']:
				top_artists.append(item)

		current_playback = requests.get("https://api.spotify.com/v1/me/player", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		if current_playback.text == '':
			current_playback = {"error": "Nothing was playing while backing up."}
		else:
			current_playback = current_playback.json()
		
		devices = requests.get("https://api.spotify.com/v1/me/player/devices", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
		
		if devices.text == '':
			devices = {"error": "No devices available."}
		else:
			devices = devices.json()

		recently_played = []
		req = requests.get("https://api.spotify.com/v1/me/player/recently-played", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})
		for item in req.json()['items']:
			recently_played.append(item)
		while "next" in req.json() and req.json()['next'] != None:
			req = requests.get(req.json()['next'], headers={
			"Authorization": f"Bearer {session['spotify_token']}"
			})
			for item in req.json()['items']:
				recently_played.append(item)

		profile = requests.get("https://api.spotify.com/v1/me", headers={
			"Authorization": f"Bearer {session['spotify_token']}"
		})

		username = profile.json()['display_name']
		os.mkdir(f"DataPak{username}/")

		f = open(f"DataPak{username}/library.json", "w")
		print({"artists": artists, "albums": albums, "playlists": playlists, "liked_songs": liked_songs, "liked_episodes": liked_episodes, "shows": shows, "top_tracks": top_tracks, "top_artists": top_artists}, file=f)
		f.close()

		f = open(f"DataPak{username}/playback.json", "w")
		print({"current_playback": current_playback, "devices": devices, "recently_played": recently_played}, file=f)
		f.close()

		f = open(f"DataPak{username}/profile.json", "w")
		print(profile.json(), file=f)
		f.close()

		shutil.make_archive(f'DataPak{username}', 'zip', f'DataPak{username}/')
		shutil.rmtree(f'DataPak{username}/')
		return send_file(f'DataPak{username}.zip', mimetype="application/zip", as_attachment=True)


@app.route('/spotify/callback')
def spotcallback():
	code = request.args.get("code")
	client_id, client_secret = os.environ['SPOTIFY_CLIENT_ID'], os.environ['SPOTIFY_CLIENT_SECRET']
	r = requests.post("https://accounts.spotify.com/api/token", data={
		"grant_type": "authorization_code",
		"type": "authorization_code",
		"code": code,
		"redirect_uri": "https://datapak.coolcodersj.repl.co/spotify/callback",
		'client_id': client_id,
		"client_secret": client_secret
	})
	session['spotify_token'] = r.json()['access_token']
	session['spotify_refresh_token'] = r.json()['refresh_token']
	return redirect('/')
	
@app.route('/github/info')
def ghinfo():
	return render_template("ghinfo.html")

@app.route('/github')
def github():
	if not "gh_token" in session:
		state = "irajfvnqehrtdfwbejktrbnvfbiwkjetrnfgcwkjenrsflwejkbtnfjbrethvbw3urskejg"
		session['state'] = state
		return redirect(f"https://github.com/login/oauth/authorize?state={state}&client_id={os.environ['GITHUB_CLIENT_ID']}&scope=repo read:repo_hook read:org read:public_key gist user read:discussion read:packages???read:gpg_key&redirect_uri=https://DataPak.coolcodersj.repl.co/github/callback")
	else:
		r = requests.get("https://api.github.com/user", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		account = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/followers", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		followers = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/following", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		following = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/gists", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		gists = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/starred", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		starred = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/subscriptions", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		watchlist = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/orgs", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		organizations = r.json()
		r = requests.get(f"https://api.github.com/users/{account['login']}/repo", headers={
			"Authorization": f"token {session['gh_token']}"
		})
		repos = r.json()
		os.mkdir(f"DataPak{account['login']}/")
		print(account, file=open(f"DataPak{account['login']}/account.json", "w"))
		print(followers, file=open(f"DataPak{account['login']}/followers.json", "w"))
		print(following, file=open(f"DataPak{account['login']}/following.json", "w"))
		print(gists, file=open(f"DataPak{account['login']}/gists.json", "w"))
		print(starred, file=open(f"DataPak{account['login']}/starred.json", "w"))
		print(watchlist, file=open(f"DataPak{account['login']}/watchlist.json", "w"))
		print(organizations, file=open(f"DataPak{account['login']}/orgs.json", "w"))
		print(repos, file=open(f"DataPak{account['login']}/repos.json", "w"))

		username = account['login']

		for repo in repos:
			name = repo['name']
			branch = repo['default_branch']			
			r = requests.get(f'https://github.com/{username}/{name}/archive/refs/heads/{branch}.zip')
			f = open(f'DataPak{username}/{name}.zip', "w+")
			print(r.content, file=f)
			f.close()

		shutil.make_archive(f'DataPak{username}', 'zip', f'DataPak{username}/')
		shutil.rmtree(f'DataPak{username}/')
		return send_file(f'DataPak{username}.zip', mimetype="application/zip", as_attachment=True)

@app.route('/github/callback')
def authorized():
	code = request.args.get("code")
	r = requests.post("https://github.com/login/oauth/access_token", data={
		"client_id": os.environ['GITHUB_CLIENT_ID'],
		"client_secret": os.environ['GITHUB_CLIENT_SECRET'],
		"code": code,
		"state": session['state']
	},
	headers={
		"Accept": "application/json"
	})
	session['gh_token'] = r.json()['access_token']
	return redirect("/")


app.run(host="0.0.0.0", port=8080)