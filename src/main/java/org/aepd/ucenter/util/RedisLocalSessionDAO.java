package org.aepd.ucenter.util;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.session.Session;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.crazycake.shiro.SerializeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RedisLocalSessionDAO extends RedisSessionDAO{

	private static Logger logger = LoggerFactory.getLogger(RedisLocalSessionDAO.class);
	private RedisManager redisManager;
	private String keyPrefix;

	public RedisLocalSessionDAO() {
		this.keyPrefix = "cas_client_session:";
	}

	public void delete(Session session) {
		super.delete(session);
	}

	public Collection<Session> getActiveSessions() {
		Set<Session> sessions = new HashSet<Session>();

		Set<byte[]> keys = this.redisManager.keys(this.keyPrefix + "*");
		if ((keys != null) && (keys.size() > 0)) {
			for (byte[] key : keys) {
				Session s = (Session) SerializeUtils.deserialize(this.redisManager.get(key));
				System.out.println("<== session 内容:==>"+ s.toString());
				sessions.add(s);
			}
		}

		return sessions;
	}

	protected Serializable doCreate(Session session) {
		Serializable sessionId = generateSessionId(session);
		//logger.info("====sessionID===="+sessionId.toString());
		logger.info("====sessionID===="+sessionId.toString());
		return super.doCreate(session);
	}

	protected Session doReadSession(Serializable sessionId) {
		return super.doReadSession(sessionId);
	}

	public RedisManager getRedisManager() {
		return this.redisManager;
	}

	public void setRedisManager(RedisManager redisManager) {
		this.redisManager = redisManager;

		this.redisManager.init();
	}

	public String getKeyPrefix() {
		return this.keyPrefix;
	}

	public void setKeyPrefix(String keyPrefix) {
		this.keyPrefix = keyPrefix;
	}

}
